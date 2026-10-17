mod greedy;
mod lazy;
mod rle;

use std::io::{self, Write};

pub(crate) use greedy::*;
pub(crate) use lazy::*;
pub(crate) use rle::*;

pub(super) const SYMBOL_LIMIT: usize = 16384;
// A lazy-parser iteration can append two literal/match pairs before checking.
const SYMBOL_CAPACITY: usize = SYMBOL_LIMIT + 4;

use crate::compress::{
    bitstream::{self, Symbol},
    matchfinder::{rle_match, Match, MatchFinder},
    BitWriter, Flush,
};

struct ParserInner<M> {
    match_finder: M,
    skip_ahead_shift: u8,

    symbols: Vec<Symbol>,

    ip: usize,
    last_match: usize,
    last_block_end: usize,
    last_index: u32,
    // Preserve match-search skipping across automatic block boundaries. This
    // score is capped independently of stream length and absolute indices.
    literal_streak: usize,
}
impl<M: MatchFinder> ParserInner<M> {
    fn new(skip_ahead_shift: u8, match_finder: M) -> Self {
        Self {
            match_finder,
            skip_ahead_shift,
            symbols: Vec::with_capacity(SYMBOL_CAPACITY),
            ip: 0,
            last_match: 0,
            last_block_end: 0,
            last_index: 0,
            literal_streak: 0,
        }
    }

    fn reset_indices(&mut self, old_base_index: u32) {
        // Parser positions are relative to the input slice. Only absolute table
        // indices and literal ranges change when rebasing the stream.
        self.last_index -= old_base_index;
        for symbol in &mut self.symbols {
            if let Symbol::LiteralRun { start, end } = symbol {
                *start -= old_base_index;
                *end -= old_base_index;
            }
        }
        self.match_finder.reset_indices(old_base_index);
    }

    fn reset(&mut self) {
        self.match_finder.clear();
        self.symbols.clear();
        self.ip = 0;
        self.last_match = 0;
        self.last_block_end = 0;
        self.last_index = 0;
        self.literal_streak = 0;
    }

    fn start_compress(&mut self, data: &[u8], base_index: u32, start: usize) -> usize {
        assert!(base_index as u64 + data.len() as u64 <= u32::MAX as u64);

        let delta = base_index - self.last_index;
        self.ip -= delta as usize;
        self.last_match -= delta as usize;
        self.last_block_end = start;
        self.last_index = base_index;
        delta as usize
    }

    #[inline(always)]
    fn get_match(&mut self, data: &[u8], base_index: u32, fizzle: bool) -> Match {
        let current = u64::from_le_bytes(data[self.ip..][..8].try_into().unwrap());
        if current as u32 == (current >> 8) as u32 {
            let m = rle_match(data, self.last_match, self.ip);
            self.ip = m.end() - 3; // Skip inserting all the totally zero values into the hash table.
            m
        } else {
            let anchor = if fizzle { self.ip } else { self.last_match };
            let mut m = self
                .match_finder
                .get_and_insert(data, base_index, anchor, self.ip, current);
            if fizzle {
                while m.length < 258
                    && m.start > self.last_match
                    && m.start > m.distance as usize + 1
                    && data[m.start - 1] == data[m.start - m.distance as usize - 1]
                {
                    m.length += 1;
                    m.start -= 1;
                }
            }
            debug_assert!(m.is_empty() || self.last_match <= m.start);
            self.ip += 1;
            m
        }
    }

    #[inline(always)]
    fn advance_to_match(&mut self, data: &[u8], base_index: u32, max_ip: usize) -> Match {
        while self.ip < max_ip {
            let m = self.get_match(data, base_index, false);
            if !m.is_empty() {
                return m;
            }

            // If we haven't found a match in a while, start skipping ahead by emitting
            // multiple literals at once.
            self.ip += (self.ip - self.last_match + self.literal_streak) >> self.skip_ahead_shift;
        }

        Match::empty()
    }

    /// Insert match finder entries for the given range.
    #[inline(always)]
    fn advance(&mut self, data: &[u8], base_index: u32, end: usize) {
        assert!(self.last_match <= self.ip);

        for j in self.ip..end.min(data.len() - 8) {
            let v = u64::from_le_bytes(data[j..][..8].try_into().unwrap());
            self.match_finder.insert(v, base_index + j as u32);
        }
        self.ip = self.ip.max(end);
    }

    #[inline(always)]
    fn insert_match(&mut self, base_index: u32, m: Match) {
        assert!(self.last_match <= m.start);
        debug_assert!(self.symbols.len() + 2 <= SYMBOL_CAPACITY);
        if m.start > self.last_match {
            self.symbols.push(Symbol::LiteralRun {
                start: base_index + self.last_match as u32,
                end: base_index + m.start as u32,
            });
        }
        self.symbols.push(Symbol::Backref {
            length: m.length,
            distance: m.distance,
            dist_sym: bitstream::distance_to_dist_sym(m.distance),
        });
        self.last_match = m.end();
        self.literal_streak = 0;
    }

    #[inline(always)]
    fn write_block_if_ready<W: Write>(
        &mut self,
        writer: &mut BitWriter<W>,
        data: &[u8],
        base_index: u32,
        flush: Flush,
    ) -> io::Result<()> {
        // Write the block if we have enough symbols.
        if self.symbols.len() >= SYMBOL_LIMIT {
            let last_block = flush == Flush::Finish && self.last_match == data.len();
            bitstream::write_block(
                writer,
                &data[self.last_block_end..self.last_match],
                base_index + self.last_block_end as u32,
                &self.symbols,
                last_block,
            )?;
            self.symbols.clear();
            self.last_block_end = self.last_match;
        }

        Ok(())
    }

    fn end_compress<W: Write>(
        &mut self,
        writer: &mut BitWriter<W>,
        data: &[u8],
        base_index: u32,
        start: usize,
        flush: Flush,
    ) -> io::Result<usize> {
        // If a flush was requested and there's remaining symbols, write another block.
        if flush != Flush::None && (!self.symbols.is_empty() || self.last_match < data.len()) {
            // The skip ahead logic can overshoot the end of the data.
            self.ip = self.ip.min(data.len());

            // Append a final literal run if there's remaining input.
            if self.last_match < data.len() {
                debug_assert!(self.symbols.len() < SYMBOL_CAPACITY);
                self.symbols.push(Symbol::LiteralRun {
                    start: base_index + self.last_match as u32,
                    end: base_index + data.len() as u32,
                });
                self.literal_streak =
                    (self.literal_streak + data.len() - self.last_match).min(1024 * 1024);
                self.ip = data.len();
                self.last_match = data.len();
            }
            assert_eq!(self.ip, data.len());

            let last_block = flush == Flush::Finish;
            bitstream::write_block(
                writer,
                &data[self.last_block_end..self.ip],
                base_index + self.last_block_end as u32,
                &self.symbols,
                last_block,
            )?;
            self.symbols.clear();
            self.last_block_end = self.ip;
        }

        let consumed = self.last_block_end - start;

        if !matches!(flush, Flush::None | Flush::Batch) {
            self.literal_streak = 0;
        }

        if flush == Flush::Full {
            self.match_finder.clear();
            self.ip = 0;
            self.last_match = 0;
            self.last_index = 0;
            self.last_block_end = 0;
            assert!(self.symbols.is_empty());
        }

        Ok(consumed)
    }
}
