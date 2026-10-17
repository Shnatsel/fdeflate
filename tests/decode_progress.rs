#![forbid(unsafe_code)]

use fdeflate::{DecompressionError, DecompressionStatus, Decompressor, Format};

#[test]
fn checksum_error_reports_progress_and_requires_reset() {
    let input = vec![42; 20000];
    let mut encoded = miniz_oxide::deflate::compress_to_vec_zlib(&input, 6);
    *encoded.last_mut().unwrap() ^= 1;
    let mut decoder = Decompressor::new();
    let mut output = vec![0; input.len()];
    let result = decoder.read_progress(&encoded, &mut output, 0);
    assert_eq!(result.consumed, encoded.len());
    assert_eq!(result.produced, input.len());
    assert!(matches!(
        result.status,
        Err(DecompressionError::WrongChecksum)
    ));
    assert_eq!(output, input);
    let result = decoder.read_progress(&encoded, &mut output, 0);
    assert_eq!((result.consumed, result.produced), (0, 0));
    assert!(matches!(
        result.status,
        Err(DecompressionError::WrongChecksum)
    ));
    decoder.reset(Format::Zlib);
    *encoded.last_mut().unwrap() ^= 1;
    let result = decoder.read_progress(&encoded, &mut output, 0);
    assert_eq!(result.status.unwrap(), DecompressionStatus::Done);
    assert_eq!(result.produced, input.len());
}

#[test]
fn error_after_valid_block_reports_its_output() {
    // Non-final stored block with one byte, then an invalid block type.
    let encoded = [0, 1, 0, 0xfe, 0xff, b'x', 7, 0];
    let mut decoder = Decompressor::new_with_format(Format::Raw);
    let mut output = [0; 100];
    let result = decoder.read_progress(&encoded, &mut output, 0);
    assert!(matches!(
        result.status,
        Err(DecompressionError::InvalidBlockType)
    ));
    assert_eq!(result.consumed, encoded.len());
    assert_eq!(result.produced, 1);
    assert_eq!(output[0], b'x');
}

#[test]
fn empty_output_can_consume_empty_blocks_and_checksum() {
    for format in [Format::Raw, Format::Zlib] {
        let encoded = if format == Format::Raw {
            miniz_oxide::deflate::compress_to_vec(&[], 0)
        } else {
            miniz_oxide::deflate::compress_to_vec_zlib(&[], 0)
        };
        let mut decoder = Decompressor::new_with_format(format);
        for (index, byte) in encoded.iter().enumerate() {
            let result = decoder.read_progress(&[*byte], &mut [], 0);
            assert_eq!((result.consumed, result.produced), (1, 0));
            assert_eq!(
                result.status.unwrap(),
                if index + 1 == encoded.len() {
                    DecompressionStatus::Done
                } else {
                    DecompressionStatus::NeedsInput
                }
            );
        }
    }
}
