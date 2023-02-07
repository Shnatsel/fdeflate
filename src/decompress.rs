use std::convert::TryInto;

use simd_adler32::Adler32;

use crate::tables::{
    CLCL_ORDER, DIST_SYM_TO_DIST_BASE, DIST_SYM_TO_DIST_EXTRA, FIXED_CODE_LENGTHS,
    LEN_SYM_TO_LEN_BASE, LEN_SYM_TO_LEN_EXTRA,
};

#[derive(Debug)]
pub enum DecompressionError {
    /// The zlib header is corrupt.
    BadZlibHeader,
    /// All input was consumed, but the end of the stream hasn't been reached.
    InsufficientInput,
    /// A block header specifies an invalid block type.
    InvalidBlockType,
    /// An uncompressed block's NLEN value is invalid.
    InvalidUncompressedBlockLength,
    /// Too many literals were specified.
    InvalidHlit,
    /// Too many distance codes were specified.
    InvalidHdist,
    /// Attempted to repeat a previous code before reading any codes, or past the end of the code
    /// lengths.
    InvalidCodeLengthRepeat,
    /// The stream doesn't specify a valid huffman tree.
    BadCodeLengthHuffmanTree,
    /// The stream doesn't specify a valid huffman tree.
    BadLiteralLengthHuffmanTree,
    /// The stream doesn't specify a valid huffman tree.
    BadDistanceHuffmanTree,
    /// The stream contains a literal/length code that was not allowed by the header.
    InvalidLiteralLengthCode,
    /// The stream contains a distance code that was not allowed by the header.
    InvalidDistanceCode,
    /// The stream contains contains back-reference as the first symbol.
    InputStartsWithRun,
    /// The stream contains a back-reference that is too far back.
    DistanceTooFarBack,
    /// The deflate stream checksum is incorrect.
    WrongChecksum,
    /// Extra input data.
    ExtraInput,
}

struct BlockHeader {
    hlit: usize,
    hdist: usize,
    num_lengths_read: usize,

    /// Low 3-bits are code length code length, high 5-bits are code length code.
    table: [u8; 128],
    code_lengths: [u8; 320],
}

/// The Decompressor state for a compressed block.
///
/// The main huffman table is `advance_table` which maps a 12 bits of literal/length symbols to
/// their meaning. Each entry is packed into a u16 using the following encoding:
///
///   000y_yyyy_yyyy_xxxx     x = input_advance_bits, y = output_advance_bytes  (x!=0)
///   000y_yyyy_xxxx_0000     x = input_advance_bits, y = symbol-256
///   1xxx_xxxx_xxxx_0000     x = secondary table index
///   1111_1111_1111_0000     invalid code
///
/// If it takes more than 12 bits to determine the meaning of the symbol, then the advance table
/// holds an index into the `secondary_table` which is added to the subsequent 3-bits from the
/// input stream. The secondary table uses the following encoding:
///
///   000y_yyyy_yyyy_xxxx     x = input_advance_bits, y = symbol
///   1111_1111_1111_1111     invalid code
///
#[repr(align(64))]
struct CompressedBlock {
    data_table: [[u8; 2]; 4096],
    advance_table: [u16; 4096],

    dist_table: [u8; 256],
    dist_symbol_lengths: [u8; 30],
    dist_symbol_masks: [u16; 30],
    dist_symbol_codes: [u16; 30],

    secondary_table: Vec<u16>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum State {
    ZlibHeader,
    BlockHeader,
    CodeLengths,
    CompressedData,
    UncompressedData,
    Checksum,
    Done,
}

/// Decompressor that reads fdeflate compressed streams.
pub struct Decompressor {
    /// State for decoding a compressed block.
    compression: CompressedBlock,
    // State for decoding a block header.
    header: BlockHeader,
    // Number of bytes left for uncompressed block.
    uncompressed_bytes_left: u16,

    buffer: u64,
    nbits: u8,
    bits_read: u64,

    queued_rle: Option<(u8, usize)>,
    queued_backref: Option<(usize, usize)>,
    last_block: bool,

    state: State,
    checksum: Adler32,
}

impl Decompressor {
    /// Create a new decompressor.
    pub fn new() -> Self {
        Self {
            buffer: 0,
            nbits: 0,
            bits_read: 0,
            compression: CompressedBlock {
                data_table: [[0; 2]; 4096],
                advance_table: [u16::MAX; 4096],
                secondary_table: Vec::new(),
                dist_table: [0; 256],
                dist_symbol_lengths: [0; 30],
                dist_symbol_masks: [0; 30],
                dist_symbol_codes: [0xffff; 30],
            },
            header: BlockHeader {
                hlit: 0,
                hdist: 0,
                table: [0; 128],
                num_lengths_read: 0,
                code_lengths: [0; 320],
            },
            uncompressed_bytes_left: 0,
            queued_rle: None,
            queued_backref: None,
            checksum: Adler32::new(),
            state: State::ZlibHeader,
            last_block: false,
        }
    }

    fn fill_buffer(&mut self, input: &mut &[u8]) {
        if self.nbits == 64 {
            /* do nothing */
        } else if input.len() >= 8 {
            self.buffer |= u64::from_le_bytes(input[..8].try_into().unwrap()) << self.nbits;
            *input = &mut &input[(63 - self.nbits as usize) / 8..];
            self.nbits |= 56;
        } else {
            let nbytes = input.len().min((64 - self.nbits as usize) / 8);
            let mut input_data = [0; 8];
            input_data[..nbytes].copy_from_slice(&input[..nbytes]);
            self.buffer |= u64::from_le_bytes(input_data) << self.nbits;
            self.nbits += nbytes as u8 * 8;
            *input = &mut &input[nbytes..];
        }
    }

    fn peak_bits(&mut self, nbits: u8) -> u64 {
        debug_assert!(nbits <= 56 && nbits <= self.nbits);
        self.buffer & ((1u64 << nbits) - 1)
    }
    fn consume_bits(&mut self, nbits: u8) {
        debug_assert!(self.nbits >= nbits);
        self.buffer >>= nbits;
        self.nbits -= nbits;
        self.bits_read += nbits as u64;
    }

    fn read_bits(&mut self, nbits: u8, input: &mut &[u8]) -> Option<u64> {
        if self.nbits < nbits {
            self.fill_buffer(input);
            if self.nbits < nbits {
                return None;
            }
        }

        let result = self.peak_bits(nbits);
        self.consume_bits(nbits);
        Some(result)
    }

    fn read_block_header(
        &mut self,
        mut remaining_input: &mut &[u8],
    ) -> Result<(), DecompressionError> {
        self.fill_buffer(remaining_input);
        if self.nbits < 3 {
            return Ok(());
        }

        let start = self.peak_bits(3);
        self.last_block = start & 1 != 0;
        match start >> 1 {
            0b00 => {
                let align_bits = (8 - ((self.bits_read + 3) % 8) as u8) % 8;
                let header_bits = 3 + 32 + align_bits;
                if self.nbits < header_bits {
                    return Ok(());
                }

                let len = (self.peak_bits(align_bits + 19) >> (align_bits + 3)) as u16;
                let nlen = (self.peak_bits(header_bits) >> (align_bits + 19)) as u16;
                if nlen != !len {
                    return Err(DecompressionError::InvalidUncompressedBlockLength);
                }

                // println!("header uncompressed last={} {len}", self.last_block);

                self.state = State::UncompressedData;
                self.uncompressed_bytes_left = len;
                self.consume_bits(header_bits);
                return Ok(());
            }
            0b01 => {
                // println!("header fixed last={}", self.last_block);
                self.consume_bits(3);
                // TODO: Do this statically rather than every time.
                self.header.hlit = 288;
                self.header.hdist = 32;
                self.header.code_lengths = FIXED_CODE_LENGTHS;
                self.build_tables()?;
                self.state = State::CompressedData;
                return Ok(());
            }
            0b10 => {
                // println!("header dynamic last={}", self.last_block);
                if self.nbits < 17 {
                    return Ok(());
                }
                let hclen = (self.peak_bits(17) >> 13) as usize + 4;
                if self.nbits as usize + remaining_input.len() * 8 < 17 + 3 * hclen {
                    return Ok(());
                }

                self.header.hlit = (self.peak_bits(8) >> 3) as usize + 257;
                self.header.hdist = (self.peak_bits(13) >> 8) as usize + 1;
                if self.header.hlit > 286 {
                    return Err(DecompressionError::InvalidHlit);
                }
                if self.header.hdist > 30 {
                    return Err(DecompressionError::InvalidHdist);
                }

                self.consume_bits(17);
                let mut code_length_lengths = [0; 19];
                for i in 0..hclen {
                    code_length_lengths[CLCL_ORDER[i]] =
                        self.read_bits(3, &mut remaining_input).unwrap() as u8;
                }
                let code_length_codes: [u16; 19] =
                    crate::compute_codes(&code_length_lengths.try_into().unwrap())
                        .ok_or(DecompressionError::BadCodeLengthHuffmanTree)?;

                self.header.table = [255; 128];
                for i in 0..19 {
                    let length = code_length_lengths[i];
                    if length > 0 {
                        let mut j = code_length_codes[i];
                        while j < 128 {
                            self.header.table[j as usize] = ((i as u8) << 3) | length;
                            j += 1 << length;
                        }
                    }
                }

                self.state = State::CodeLengths;
                return Ok(());
            }
            0b11 => return Err(DecompressionError::InvalidBlockType),
            _ => unreachable!(),
        }
    }

    fn read_code_lengths(&mut self, remaining_input: &mut &[u8]) -> Result<(), DecompressionError> {
        let total_lengths = self.header.hlit + self.header.hdist;
        while self.header.num_lengths_read < total_lengths {
            self.fill_buffer(remaining_input);
            if self.nbits < 7 {
                return Ok(());
            }

            let code = self.peak_bits(7);
            let entry = self.header.table[code as usize];
            let length = entry & 0x7;
            let symbol = entry >> 3;

            debug_assert!(length != 0);
            match symbol {
                0..=15 => {
                    self.header.code_lengths[self.header.num_lengths_read] = symbol;
                    self.header.num_lengths_read += 1;
                    self.consume_bits(length);
                }
                16 | 17 | 18 => {
                    let (base_repeat, extra_bits) = match symbol {
                        16 => (3, 2),
                        17 => (3, 3),
                        18 => (11, 7),
                        _ => unreachable!(),
                    };

                    if self.nbits < length + extra_bits {
                        return Ok(());
                    }

                    let value = match symbol {
                        16 => {
                            self.header.code_lengths[self
                                .header
                                .num_lengths_read
                                .checked_sub(1)
                                .ok_or(DecompressionError::InvalidCodeLengthRepeat)?]
                            // TODO: is this right?
                        }
                        17 => 0,
                        18 => 0,
                        _ => unreachable!(),
                    };

                    let repeat =
                        (self.peak_bits(length + extra_bits) >> length) as usize + base_repeat;
                    if self.header.num_lengths_read + repeat > total_lengths {
                        return Err(DecompressionError::InvalidCodeLengthRepeat);
                    }

                    for i in 0..repeat {
                        self.header.code_lengths[self.header.num_lengths_read + i] = value;
                    }
                    self.header.num_lengths_read += repeat;
                    self.consume_bits(length + extra_bits);
                }
                _ => unreachable!(),
            }
        }

        self.header
            .code_lengths
            .copy_within(self.header.hlit..total_lengths, 288);
        for i in self.header.hlit..288 {
            self.header.code_lengths[i] = 0;
        }
        for i in 288 + self.header.hdist..320 {
            self.header.code_lengths[i] = 0;
        }

        self.build_tables()?;
        self.state = State::CompressedData;
        Ok(())
    }

    fn build_tables(&mut self) -> Result<(), DecompressionError> {
        // Build the literal/length code table.
        let lengths = &self.header.code_lengths[..288];
        let codes: [u16; 288] = crate::compute_codes(&lengths.try_into().unwrap())
            .ok_or(DecompressionError::BadLiteralLengthHuffmanTree)?;

        // Check whether literal zero is assigned code zero. If so, our table can encode entries
        // with 3+ symbols even though each entry has only 2 data bytes.
        let use_extra_length = lengths[0] > 0 && codes[0] == 0;

        for i in 0..256 {
            let code = codes[i];
            let length = lengths[i];
            let mut j = code;

            while j < 4096 && length != 0 && length <= 12 {
                let extra_length = if use_extra_length {
                    ((j | 0xf000) >> length).trailing_zeros() as u8 / lengths[0]
                } else {
                    0
                };

                self.compression.data_table[j as usize][0] = i as u8;
                self.compression.advance_table[j as usize] =
                    ((extra_length as u16 + 1) << 4) | (length + extra_length * lengths[0]) as u16;
                j += 1 << length;
            }

            if length > 0 && length <= 9 {
                for ii in 0..256 {
                    let code2 = codes[ii];
                    let length2 = lengths[ii];
                    if length2 != 0 && length + length2 <= 12 {
                        let mut j = code | (code2 << length);

                        while j < 4096 {
                            let extra_length = if use_extra_length {
                                ((j | 0xf000) >> (length + length2)).trailing_zeros() as u8
                                    / lengths[0]
                            } else {
                                0
                            };

                            self.compression.data_table[j as usize][0] = i as u8;
                            self.compression.data_table[j as usize][1] = ii as u8;
                            self.compression.advance_table[j as usize] = (extra_length as u16 + 2)
                                << 4
                                | (length + length2 + extra_length * lengths[0]) as u16;
                            j += 1 << (length + length2);
                        }
                    }
                }
            }
        }
        for i in 256..self.header.hlit {
            let code = codes[i];
            let length = lengths[i];
            if length != 0 && length <= 12 {
                let mut j = code;
                while j < 4096 && length != 0 {
                    self.compression.advance_table[j as usize] =
                        (i as u16 - 256) << 8 | (length as u16) << 4;
                    j += 1 << length;
                }
            }
        }

        for i in 0..self.header.hlit {
            if lengths[i] > 12 {
                self.compression.advance_table[(codes[i] & 0xfff) as usize] = u16::MAX;
            }
        }

        let mut secondary_table_len = 0;
        for i in 0..self.header.hlit {
            if lengths[i] > 12 {
                let j = (codes[i] & 0xfff) as usize;
                if self.compression.advance_table[j] == u16::MAX {
                    self.compression.advance_table[j] = (secondary_table_len << 4) | 0x8000;
                    secondary_table_len += 8;
                }
            }
        }
        assert!(secondary_table_len <= 0x7ff);
        self.compression.secondary_table = vec![0; secondary_table_len as usize];
        for i in 0..self.header.hlit {
            let code = codes[i];
            let length = lengths[i];
            if length > 12 {
                let j = (codes[i] & 0xfff) as usize;
                let k = (self.compression.advance_table[j] & 0x7ff0) >> 4;

                let mut s = code >> 12;
                while s < 8 {
                    debug_assert_eq!(self.compression.secondary_table[k as usize + s as usize], 0);
                    self.compression.secondary_table[k as usize + s as usize] =
                        ((i as u16) << 4) | (length as u16);
                    s += 1 << (length - 12);
                }
            }
        }
        debug_assert!(self
            .compression
            .secondary_table
            .iter()
            .all(|&x| x != 0 && (x & 0xf) > 12));

        // Build the distance code table.
        let lengths = &self.header.code_lengths[288..320];
        if lengths == [0; 32] {
            self.compression.dist_symbol_masks = [0; 30];
            self.compression.dist_symbol_codes = [0xffff; 30];
            self.compression.dist_table.fill(0);
        } else {
            let codes: [u16; 32] = match crate::compute_codes(&lengths.try_into().unwrap()) {
                Some(codes) => codes,
                None => {
                    if lengths.iter().filter(|&&l| l != 0).count() != 1 {
                        println!("{:?}", lengths);
                        return Err(DecompressionError::BadDistanceHuffmanTree);
                    }
                    self.compression.dist_table.fill(0);
                    [0; 32]
                }
            };

            self.compression
                .dist_symbol_codes
                .copy_from_slice(&codes[..30]);
            self.compression
                .dist_symbol_lengths
                .copy_from_slice(&lengths[..30]);
            for i in 0..30 {
                if lengths[i] == 0 {
                    self.compression.dist_symbol_masks[i] = 0;
                    self.compression.dist_symbol_codes[i] = 0xffff;
                } else {
                    self.compression.dist_symbol_masks[i] = (1 << lengths[i]) - 1;
                    // let mut j = codes[i];
                    // while j < 256 {
                    //     self.compression.dist_table[j as usize] = i as u8;
                    //     j += 1 << lengths[i];
                    // }
                }
            }

            // TODO
            self.compression.dist_table.fill(0);
        }

        Ok(())
    }

    fn read_compressed(
        &mut self,
        remaining_input: &mut &[u8],
        output: &mut [u8],
        mut output_index: usize,
    ) -> Result<usize, DecompressionError> {
        // Main decoding loop
        while let State::CompressedData = self.state {
            self.fill_buffer(remaining_input);

            // // Ultra-fast path: do 4 consecutive table lookups and bail if any of them need the slow path.
            // if self.nbits >= 48 {
            //     let bits = self.peak_bits(48);
            //     let advance0 = self.compression.advance_table[(bits & 0xfff) as usize];
            //     let advance0_input_bits = advance0 & 0xf;
            //     let advance1 =
            //         self.compression.advance_table[(bits >> advance0_input_bits) as usize & 0xfff];
            //     let advance1_input_bits = advance1 & 0xf;
            //     let advance2 = self.compression.advance_table
            //         [(bits >> (advance0_input_bits + advance1_input_bits)) as usize & 0xfff];
            //     let advance2_input_bits = advance2 & 0xf;
            //     let advance3 = self.compression.advance_table[(bits
            //         >> (advance0_input_bits + advance1_input_bits + advance2_input_bits))
            //         as usize
            //         & 0xfff];
            //     let advance3_input_bits = advance3 & 0xf;

            //     if advance0_input_bits > 0
            //         && advance1_input_bits > 0
            //         && advance2_input_bits > 0
            //         && advance3_input_bits > 0
            //     {
            //         let advance0_output_bytes = (advance0 >> 4) as usize;
            //         let advance1_output_bytes = (advance1 >> 4) as usize;
            //         let advance2_output_bytes = (advance2 >> 4) as usize;
            //         let advance3_output_bytes = (advance3 >> 4) as usize;

            //         if output_index
            //             + advance0_output_bytes
            //             + advance1_output_bytes
            //             + advance2_output_bytes
            //             + advance3_output_bytes
            //             < output.len()
            //         {
            //             let data0 = self.compression.data_table[(bits & 0xfff) as usize];
            //             let data1 = self.compression.data_table
            //                 [(bits >> advance0_input_bits) as usize & 0xfff];
            //             let data2 = self.compression.data_table[(bits
            //                 >> (advance0_input_bits + advance1_input_bits))
            //                 as usize
            //                 & 0xfff];
            //             let data3 = self.compression.data_table[(bits
            //                 >> (advance0_input_bits + advance1_input_bits + advance2_input_bits))
            //                 as usize
            //                 & 0xfff];

            //             let advance = advance0_input_bits
            //                 + advance1_input_bits
            //                 + advance2_input_bits
            //                 + advance3_input_bits;
            //             self.consume_bits(advance as u8);

            //             output[output_index] = data0[0];
            //             output[output_index + 1] = data0[1];
            //             output_index += advance0_output_bytes;
            //             output[output_index] = data1[0];
            //             output[output_index + 1] = data1[1];
            //             output_index += advance1_output_bytes;
            //             output[output_index] = data2[0];
            //             output[output_index + 1] = data2[1];
            //             output_index += advance2_output_bytes;
            //             output[output_index] = data3[0];
            //             output[output_index + 1] = data3[1];
            //             output_index += advance3_output_bytes;
            //             continue;
            //         }
            //     }
            // }

            if self.nbits < 15 {
                break;
            }

            let table_index = self.peak_bits(12);
            let data = self.compression.data_table[table_index as usize];
            let advance = self.compression.advance_table[table_index as usize];

            let advance_input_bits = (advance & 0x0f) as u8;
            let advance_output_bytes = (advance >> 4) as usize;

            // Fast path: if the next symbol is <= 12 bits and a literal, the table specifies the
            // output bytes and we can directly write them to the output buffer.
            if advance_input_bits > 0 {
                if output_index + 1 < output.len() {
                    output[output_index] = data[0];
                    output[output_index + 1] = data[1];
                    output_index += advance_output_bytes;
                    self.consume_bits(advance_input_bits);

                    // println!("code = {:b}", table_index & ((1 << advance_input_bits) - 1));
                    // match advance_output_bytes {
                    //     0 => unreachable!(),
                    //     1 => println!("[{output_index}] data1 {:x}", data[0]),
                    //     2 => println!("[{output_index}] data2 {:x} {:x}", data[0], data[1]),
                    //     n => println!("[{output_index}] dataN {:x} {:x} n={}", data[0], data[1], n),
                    // }

                    if output_index > output.len() {
                        self.queued_rle = Some((0, output_index - output.len()));
                        output_index = output.len();
                        break;
                    } else {
                        continue;
                    }
                } else if output_index + advance_output_bytes == output.len() {
                    debug_assert_eq!(advance_output_bytes, 1);
                    output[output_index] = data[0];
                    output_index += 1;
                    self.consume_bits(advance_input_bits);
                    break;
                } else {
                    break;
                }
            }

            // Slow path: the next symbol is a length symbol and/or is more than 12 bits.
            let (litlen_code_bits, litlen_symbol) = if advance & 0x8000 == 0 {
                (
                    (advance_output_bytes & 0x0f) as u8,
                    256 + (advance_output_bytes >> 4) as usize,
                )
            } else if advance != 0xfff0 {
                let next3 = self.peak_bits(15) >> 12;
                let secondary_index = (advance & 0x7ff0) >> 4;
                let secondary =
                    self.compression.secondary_table[secondary_index as usize + next3 as usize];
                ((secondary & 0xf) as u8, (secondary >> 4) as usize)
            } else {
                return Err(DecompressionError::InvalidLiteralLengthCode);
            };

            if litlen_symbol < 256 {
                // println!("[{output_index}] slow1 {litlen_symbol} {litlen_code_bits}");
                // literal
                if output_index >= output.len() {
                    break;
                }
                output[output_index] = litlen_symbol as u8;
                output_index += 1;
                self.consume_bits(litlen_code_bits);
                continue;
            } else if litlen_symbol == 256 {
                // println!("[{output_index}] slow1 EOF {litlen_code_bits}");
                // end of block
                self.consume_bits(litlen_code_bits);
                self.state = if self.last_block {
                    State::Checksum
                } else {
                    State::BlockHeader
                };
                break;
            } else if litlen_symbol > 285 {
                return Err(DecompressionError::InvalidLiteralLengthCode);
            }

            let length_extra_bits = LEN_SYM_TO_LEN_EXTRA[litlen_symbol - 257];
            if self.nbits < length_extra_bits + litlen_code_bits + 28 {
                break;
            }

            let bits =
                self.peak_bits(length_extra_bits + litlen_code_bits + 28) >> litlen_code_bits;
            let length_code = bits & ((1 << length_extra_bits) - 1);
            let dist_code = ((bits >> length_extra_bits) & 0x7fff) as u16;
            let length = LEN_SYM_TO_LEN_BASE[litlen_symbol - 257] + length_code as usize;

            if dist_code & self.compression.dist_symbol_masks[0]
                == self.compression.dist_symbol_codes[0]
                && false
            {
                // println!("[{output_index}] rle{length} {litlen_symbol}");

                let last = if output_index > 0 {
                    output[output_index - 1]
                } else {
                    return Err(DecompressionError::InputStartsWithRun);
                };

                self.consume_bits(
                    length_extra_bits + litlen_code_bits + self.compression.dist_symbol_lengths[0],
                );

                // fdeflate only writes runs of zeros, but handling non-zero runs isn't hard and
                // it is too late to bail now.
                if last != 0 {
                    let end = (output_index + length).min(output.len());
                    output[output_index..end].fill(last);
                }

                // The run can easily extend past the end of the output buffer. If so, queue the
                // output for the next call and break.
                if output_index + length > output.len() {
                    self.queued_rle = Some((last, output_index + length - output.len()));
                    output_index = output.len();
                    break;
                } else {
                    output_index += length;
                }
            } else {
                let mut dist_symbol = 999;
                for j in self.compression.dist_table[dist_code as usize & 0xFF] as usize..30 {
                    if dist_code & self.compression.dist_symbol_masks[j]
                        == self.compression.dist_symbol_codes[j]
                    {
                        dist_symbol = j;
                        break;
                    }
                }
                if dist_symbol == 999 {
                    return Err(DecompressionError::InvalidDistanceCode);
                }

                let dist_code_bits = self.compression.dist_symbol_lengths[dist_symbol];
                let dist_extra_bits = DIST_SYM_TO_DIST_EXTRA[dist_symbol];
                let dist_extra_mask = (1 << dist_extra_bits) - 1;
                let dist = DIST_SYM_TO_DIST_BASE[dist_symbol] as usize
                    + ((bits >> (length_extra_bits + dist_code_bits)) & dist_extra_mask) as usize;

                if dist > output_index {
                    return Err(DecompressionError::DistanceTooFarBack);
                }
                // println!("[{output_index}] backref{length} {dist}");

                let copy_length = length.min(output.len() - output_index);
                if dist < copy_length {
                    for i in 0..copy_length {
                        output[output_index + i] = output[output_index + i - dist];
                    }
                } else {
                    output.copy_within(
                        output_index - dist..output_index + copy_length - dist,
                        output_index,
                    )
                }
                output_index += copy_length;

                self.consume_bits(
                    litlen_code_bits + length_extra_bits + dist_code_bits + dist_extra_bits,
                );

                if copy_length < length {
                    self.queued_backref = Some((dist, length - copy_length));
                    break;
                }
            }
        }
        Ok(output_index)
    }

    /// Decompresses a chunk of data.
    ///
    /// Returns the number of bytes read from `input` and the number of bytes written to `output`,
    /// or an error if the deflate stream is not valid. `input` is the compressed data. `output`
    /// is the buffer to write the decompressed data to. `end_of_input` indicates whether more
    /// data may be available in the future.
    pub fn read(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        output_position: usize,
        end_of_input: bool,
    ) -> Result<(usize, usize), DecompressionError> {
        if let State::Done = self.state {
            return Ok((0, 0));
        }

        assert!(output.len() >= output_position + 2);
        debug_assert!(output[output_position..].iter().all(|&b| b == 0));

        let mut remaining_input = &input[..];
        let mut output_index = output_position;

        if let Some((data, len)) = self.queued_rle.take() {
            let n = len.min(output.len() - output_index);
            if data != 0 {
                output[output_index..][..n].fill(data);
            }
            output_index += n;
            if n < len {
                self.queued_rle = Some((data, len - n));
                return Ok((0, n));
            }
        }
        if let Some((dist, len)) = self.queued_backref {
            // println!("queued backref{len} {dist}");
            let n = len.min(output.len() - output_index);
            for i in 0..n {
                output[output_index + i] = output[output_index + i - dist];
            }
            output_index += n;
            if n < len {
                self.queued_backref = Some((dist, len - n));
                return Ok((0, n));
            }
        }

        // Main decoding state machine.
        let mut last_state = None;
        while last_state != Some(self.state) {
            last_state = Some(self.state);
            match self.state {
                State::ZlibHeader => {
                    if input.len() < 2 && !end_of_input {
                        return Ok((0, 0));
                    } else if input.len() < 2 {
                        return Err(DecompressionError::InsufficientInput);
                    }

                    if input[0] & 0x0f != 0x08
                        || (input[0] & 0xf0) > 0x70
                        || input[1] & 0x20 != 0
                        || u16::from_be_bytes(input[..2].try_into().unwrap()) % 31 != 0
                    {
                        return Err(DecompressionError::BadZlibHeader);
                    }

                    remaining_input = &remaining_input[2..];
                    self.state = State::BlockHeader;
                }
                State::BlockHeader => {
                    self.read_block_header(&mut remaining_input)?;
                }
                State::CodeLengths => {
                    self.read_code_lengths(&mut remaining_input)?;
                }
                State::CompressedData => {
                    output_index =
                        self.read_compressed(&mut remaining_input, output, output_index)?
                }
                State::UncompressedData => {
                    // Drain any bytes from our buffer.
                    debug_assert_eq!(self.nbits % 8, 0);
                    while self.nbits > 0
                        && self.uncompressed_bytes_left > 0
                        && output_index < output.len()
                    {
                        output[output_index] = self.peak_bits(8) as u8;
                        self.consume_bits(8);
                        output_index += 1;
                        self.uncompressed_bytes_left -= 1;
                    }
                    // Buffer may contain one additional byte. Clear it to avoid confusion.
                    self.buffer = 0;

                    // Copy subsequent bytes directly from the input.
                    let copy_bytes = (self.uncompressed_bytes_left as usize)
                        .min(remaining_input.len())
                        .min(output.len() - output_index);
                    // println!("uncompressed {:02x?}", &remaining_input[..copy_bytes.min(16)]);
                    output[output_index..][..copy_bytes]
                        .copy_from_slice(&remaining_input[..copy_bytes]);
                    remaining_input = &remaining_input[copy_bytes..];
                    output_index += copy_bytes;
                    self.uncompressed_bytes_left -= copy_bytes as u16;

                    if self.uncompressed_bytes_left == 0 {
                        self.state = if self.last_block {
                            State::Checksum
                        } else {
                            State::BlockHeader
                        };
                    }
                }
                State::Checksum => {
                    self.fill_buffer(&mut remaining_input);

                    let align_bits = (8 - (self.bits_read % 8) as u8) % 8;
                    if self.nbits >= 32 + align_bits {
                        self.checksum.write(&output[output_position..output_index]);
                        if align_bits != 0 {
                            self.consume_bits(align_bits);
                        }
                        #[cfg(not(fuzzing))]
                        if (self.peak_bits(32) as u32).swap_bytes() != self.checksum.finish() {
                            // println!(
                            //     "checksum mismatch: {:x} != {:x}",
                            //     (self.peak_bits(32) as u32).swap_bytes(),
                            //     self.checksum.finish()
                            // );
                            return Err(DecompressionError::WrongChecksum);
                        }
                        self.state = State::Done;
                        self.consume_bits(32);
                        break;
                    }
                }
                State::Done => unreachable!(),
            }
        }

        if self.state != State::Done {
            self.checksum.write(&output[output_position..output_index]);
        }

        if self.state == State::Done || !end_of_input || output_index >= output.len() - 1 {
            let input_left = remaining_input.len();
            Ok((input.len() - input_left, output_index - output_position))
        } else {
            Err(DecompressionError::InsufficientInput)
        }
    }

    /// Returns true if the decompressor has finished decompressing the input.
    pub fn done(&self) -> bool {
        self.state == State::Done
    }
}

/// Decompresses the given input. Returns an error if the input is invalid.
pub fn decompress_to_vec(input: &[u8]) -> Result<Vec<u8>, DecompressionError> {
    let mut decoder = Decompressor::new();
    let mut output = vec![0; 1024];
    let mut input_index = 0;
    let mut output_index = 0;
    while !decoder.done() {
        let (consumed, produced) =
            decoder.read(&input[input_index..], &mut output, output_index, true)?;
        input_index += consumed;
        output_index += produced;
        output.resize(output_index + 32 * 1024, 0);
    }
    output.resize(output_index, 0);

    // if input_index != input.len() {
    //     println!("extra input: {} bytes", input.len() - input_index);
    //     Err(DecompressionError::ExtraInput)
    // } else {
    Ok(output)
    // }
}

#[cfg(test)]
mod tests {
    use crate::tables::{LENGTH_TO_LEN_EXTRA, LENGTH_TO_SYMBOL};

    use super::*;
    use rand::Rng;
    use std::io::Read;

    fn roundtrip(data: &[u8]) {
        let compressed = crate::compress_to_vec(data);
        let decompressed = decompress_to_vec(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }

    fn roundtrip_miniz_oxide(data: &[u8]) {
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(data, 3);
        let decompressed = decompress_to_vec(&compressed).unwrap();
        assert_eq!(decompressed.len(), data.len());
        for (i, (a, b)) in decompressed.chunks(1).zip(data.chunks(1)).enumerate() {
            assert_eq!(a, b, "chunk {}..{}", i * 1, i * 1 + 1);
        }
        assert_eq!(&decompressed, data);
    }

    fn compare_decompression(data: &[u8]) {
        // let decompressed0 = flate2::read::ZlibDecoder::new(std::io::Cursor::new(&data))
        //     .bytes()
        //     .collect::<Result<Vec<_>, _>>()
        //     .unwrap();
        let decompressed = decompress_to_vec(&data).unwrap();
        let decompressed2 = miniz_oxide::inflate::decompress_to_vec_zlib(&data).unwrap();
        for (i, (a, b)) in decompressed
            .chunks(1)
            .zip(decompressed2.chunks(1))
            .enumerate()
        {
            assert_eq!(a, b, "index {i}");
        }
        if decompressed != decompressed2 {
            panic!("length mismatch {} {} {:x?}", decompressed.len(), decompressed2.len(), &decompressed2[decompressed.len()..][..16]);
        }
        //assert_eq!(decompressed, decompressed2);
    }

    #[test]
    fn tables() {
        for (i, &bits) in LEN_SYM_TO_LEN_EXTRA.iter().enumerate() {
            let len_base = LEN_SYM_TO_LEN_BASE[i];
            for j in 0..(1 << bits) {
                if i == 27 && j == 31 {
                    continue;
                }
                assert_eq!(LENGTH_TO_LEN_EXTRA[len_base + j - 3], bits, "{} {}", i, j);
                assert_eq!(
                    LENGTH_TO_SYMBOL[len_base + j - 3],
                    i as u16 + 257,
                    "{} {}",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn it_works() {
        roundtrip(b"Hello world!");
    }

    #[test]
    fn constant() {
        roundtrip_miniz_oxide(&vec![0; 50]);
        roundtrip_miniz_oxide(&vec![5; 2048]);
        roundtrip_miniz_oxide(&vec![128; 2048]);
        roundtrip_miniz_oxide(&vec![254; 2048]);
    }

    #[test]
    fn random() {
        let mut rng = rand::thread_rng();
        let mut data = vec![0; 50000];
        for _ in 0..10 {
            for byte in &mut data {
                *byte = rng.gen::<u8>() % 5;
            }
            println!("Random data: {:?}", data);
            roundtrip_miniz_oxide(&data);
        }
    }

    #[test]
    fn simple() {
        compare_decompression(&[
            120, 1, 154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0, 0, 41, 41, 169, 93, 41, 255, 0, 0, 0,
            13, 120, 1, 237, 224, 1, 144, 36, 73, 146, 36, 73, 18, 139, 0, 0, 0, 16, 0, 0, 0, 0, 0,
            0, 0, 0, 204, 204, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 170, 153, 187, 71, 68, 68, 102, 102, 102, 86, 117, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 78, 85, 85, 119, 119, 119, 119, 119, 247, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 255, 255, 255, 255, 255, 255, 0, 108, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 203, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 120, 1, 5, 224, 1, 144, 36, 73, 146, 36, 73, 18, 139, 170, 153, 187, 71, 68, 68,
            154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0, 0, 40, 41, 41, 41, 169, 255, 0, 0, 0, 13,
            120, 1, 237, 224, 1, 144, 32, 146, 36, 73, 18, 139, 0, 0, 0, 16, 0, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            68, 102, 102, 102, 86, 117, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 78, 85, 85, 119, 119, 119, 119, 119,
            247, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 255, 255, 255, 255,
            255, 255, 0, 108, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 120, 1, 5, 224, 1, 144, 36, 73, 146,
            36, 73, 18, 139, 170, 153, 187, 71, 68, 68, 154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0,
            0, 93, 41, 41, 41, 169, 255, 0, 0, 0, 13, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 153, 187,
            71, 68, 68, 102, 102, 102, 86, 117, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 78, 85, 85, 119, 119, 119,
            119, 119, 247, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 255, 255,
            255, 255, 255, 255, 0, 108, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 203, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 120, 1, 5, 224, 1, 144, 36,
            73, 146, 36, 73, 18, 139, 170, 153, 187, 71, 68, 68, 154, 41, 120, 1, 0, 255, 0, 0,
            255, 1, 0, 0, 40, 41, 41, 41, 169, 255, 0, 0, 0, 13, 120, 1, 237, 224, 1, 144, 32, 146,
            36, 73, 18, 139, 0, 0, 0, 16, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 63, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 102, 102, 102, 86, 117, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 78, 85, 85, 119, 119, 119, 119, 119, 247, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 255, 255, 255, 255, 255, 255, 0, 108, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
            204, 204, 204, 120, 1, 5, 224, 1, 144, 36, 73, 146, 36, 73, 18, 139, 170, 153, 187, 71,
            68, 68, 154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0, 0, 93, 41, 41, 41, 169, 255, 0, 0, 0,
            13, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
            239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 255, 255, 255,
            255, 255, 255, 0, 108, 144, 32, 146, 36, 73, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
            18, 139, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1, 5, 224, 1, 144, 36, 73, 146, 36, 73, 18, 139, 170, 153, 187, 71,
            68, 68, 154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0, 0, 93, 41, 41, 41, 169, 255, 0, 0, 0,
            13, 120, 1, 237, 224, 1, 144, 32, 146, 36, 73, 18, 139, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 224, 1, 144, 36, 73, 146, 36, 73, 18, 139, 187,
            71, 68, 68, 154, 41, 120, 1, 0, 255, 0, 0, 255, 1, 0, 0, 93, 41, 41, 41, 169, 255, 0,
            0, 0, 13, 120, 1, 237, 224, 1, 144, 0, 68, 102, 230, 102, 86, 85, 85, 85, 85, 119, 119,
            119, 119, 119, 247, 204, 204, 204, 204, 204, 0, 0, 204, 204,
        ]);
    }
}
