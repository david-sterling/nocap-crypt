//! Pure alignment math plus an aligned-memory buffer, used by both the
//! `align check`/`align fix` subcommands and internally by `SectorFile`
//! when O_DIRECT is active (which requires page/sector-aligned buffers,
//! offsets, and lengths — getting this wrong means silent corruption or
//! `EINVAL` from the kernel).

pub fn is_aligned(value: u64, alignment: u64) -> bool {
    value.is_multiple_of(alignment)
}

/// Round `value` up to the next multiple of `alignment`.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    let rem = value % alignment;
    if rem == 0 {
        value
    } else {
        value + (alignment - rem)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignmentReport {
    pub required_alignment: u64,
    pub file_size: u64,
    pub file_size_aligned: bool,
    pub offset: u64,
    pub offset_aligned: bool,
}

impl AlignmentReport {
    pub fn passes(&self) -> bool {
        self.file_size_aligned && self.offset_aligned
    }
}

/// Check whether `file_size`/`offset` satisfy `alignment` (the
/// device's logical/physical sector size, typically 512 or 4096).
pub fn check_alignment(file_size: u64, offset: u64, alignment: u64) -> AlignmentReport {
    AlignmentReport {
        required_alignment: alignment,
        file_size,
        file_size_aligned: is_aligned(file_size, alignment),
        offset,
        offset_aligned: is_aligned(offset, alignment),
    }
}

/// A `len`-byte buffer whose start address is aligned to `alignment`
/// bytes — required for O_DIRECT reads/writes on Linux. Implemented as
/// an over-allocated `Vec<u8>` sliced at the first aligned offset,
/// since Rust's allocator doesn't expose over-alignment for arbitrary
/// runtime alignments without `std::alloc` plumbing.
pub struct AlignedBuffer {
    data: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedBuffer {
    pub fn new(len: usize, alignment: usize) -> Self {
        assert!(
            alignment.is_power_of_two(),
            "alignment must be a power of two"
        );
        let mut data = vec![0u8; len + alignment];
        let base = data.as_ptr() as usize;
        let aligned = (base + alignment - 1) & !(alignment - 1);
        let start = aligned - base;
        data.truncate(start + len);
        Self { data, start, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.start + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.start + self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_aligned_basic() {
        assert!(is_aligned(0, 512));
        assert!(is_aligned(4096, 512));
        assert!(!is_aligned(513, 512));
    }

    #[test]
    fn align_up_rounds_correctly() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test]
    fn check_alignment_reports_both_axes() {
        let report = check_alignment(8192, 512, 4096);
        assert!(report.file_size_aligned);
        assert!(!report.offset_aligned);
        assert!(!report.passes());
    }

    #[test]
    fn aligned_buffer_start_address_is_aligned() {
        for alignment in [512usize, 4096] {
            let buf = AlignedBuffer::new(4096, alignment);
            let addr = buf.as_slice().as_ptr() as usize;
            assert_eq!(addr % alignment, 0, "alignment={alignment}");
            assert_eq!(buf.len(), 4096);
        }
    }

    #[test]
    fn aligned_buffer_is_writable_and_readable() {
        let mut buf = AlignedBuffer::new(16, 512);
        buf.as_mut_slice()
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(buf.as_slice()[0], 1);
        assert_eq!(buf.as_slice()[15], 16);
    }
}
