//! Aligned, random-access file I/O: `SectorFile` wraps a `std::fs::File`
//! with `pread`/`pwrite`-style offset-based access (required since
//! `plain64` sector dispatch is inherently random-access, not
//! streaming — see `nocap-crypt-core`), attempting O_DIRECT on Linux with
//! a transparent fallback to buffered I/O when the target filesystem
//! doesn't support it (common for overlayfs inside a build container,
//! which is exactly this tool's actual runtime environment).

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use crate::alignment::AlignedBuffer;

/// Safe for every real device's O_DIRECT logical-block-size minimum
/// (512 or 4096 bytes) — a page is always a multiple of either.
const DIRECT_IO_ALIGNMENT: usize = 4096;

/// True if the file was opened with O_DIRECT successfully active;
/// false if it fell back to ordinary buffered I/O. Reported in
/// verbose/didactic mode rather than failing silently or crashing on
/// `EINVAL`.
pub struct SectorFile {
    file: File,
    direct_io_active: bool,
    /// Kept only to open a short-lived, non-`O_DIRECT` handle for the
    /// one case `write_at` can't push through the `O_DIRECT` handle
    /// directly — see that method.
    path: PathBuf,
}

impl SectorFile {
    pub fn open_read(path: &Path) -> io::Result<Self> {
        let (file, direct_io_active) = platform::open_read(path)?;
        Ok(Self {
            file,
            direct_io_active,
            path: path.to_path_buf(),
        })
    }

    /// Open for read+write, creating the file if `create` is set.
    pub fn open_write(path: &Path, create: bool) -> io::Result<Self> {
        let (file, direct_io_active) = platform::open_write(path, create)?;
        Ok(Self {
            file,
            direct_io_active,
            path: path.to_path_buf(),
        })
    }

    pub fn direct_io_active(&self) -> bool {
        self.direct_io_active
    }

    /// O_DIRECT has two alignment requirements beyond the file offset:
    /// the buffer's *memory address* must be aligned (Rust's allocator
    /// makes no such promise for an ordinary `Vec<u8>`), and the
    /// *transfer length* must be aligned too. The second one bites
    /// specifically on the last, real-EOF-bounded read of a file whose
    /// size isn't a whole number of sectors (`available` in
    /// `nocap-crypt-worker::dispatch` is deliberately short there) —
    /// so the kernel-facing read always requests a rounded-up, aligned
    /// length via an [`AlignedBuffer`], and only the caller's
    /// originally-requested prefix (capped at however many bytes the
    /// kernel actually returned, for genuine EOF) is copied back out.
    /// When direct I/O isn't active (buffered fallback), neither
    /// requirement applies and this is a plain passthrough.
    ///
    /// Both requirements are easy to satisfy by accident in casual
    /// testing (large allocations often land on a page boundary; small
    /// test files often aren't the case that exercises a short,
    /// non-sector-aligned EOF read), so don't assume either is
    /// unnecessary just because it doesn't reproduce locally — this
    /// whole `O_DIRECT` path is `#[cfg(target_os = "linux")]` and
    /// untested on a Windows dev machine.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if self.direct_io_active && !buf.is_empty() {
            let aligned_len = buf.len().next_multiple_of(DIRECT_IO_ALIGNMENT);
            let mut scratch = AlignedBuffer::new(aligned_len, DIRECT_IO_ALIGNMENT);
            let n = platform::read_at(&self.file, offset, scratch.as_mut_slice())?;
            let n = n.min(buf.len());
            buf[..n].copy_from_slice(&scratch.as_slice()[..n]);
            Ok(n)
        } else {
            platform::read_at(&self.file, offset, buf)
        }
    }

    /// See [`Self::read_at`] for the memory-alignment half — same
    /// bounce-through-aligned-scratch treatment. The transfer-*length*
    /// half can't be mirrored the same way: `read_at` covers a short
    /// final read by requesting a rounded-up length and discarding the
    /// extra bytes the kernel hands back, but a write actually
    /// persists whatever length it's given — padding a short final
    /// write up to the alignment boundary would write past the file's
    /// intended length (real headerless `plain` volumes are only
    /// 512-byte-sector-aligned, not necessarily a `DIRECT_IO_ALIGNMENT`
    /// multiple). So a non-aligned length instead goes through a
    /// short-lived, non-`O_DIRECT` handle on the same path, which has
    /// no alignment requirement at all; only the one call pays that
    /// cost, since chunk dispatch only ever produces one short range
    /// per file (the tail).
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        if self.direct_io_active && !buf.is_empty() {
            if buf.len().is_multiple_of(DIRECT_IO_ALIGNMENT) {
                let mut scratch = AlignedBuffer::new(buf.len(), DIRECT_IO_ALIGNMENT);
                scratch.as_mut_slice().copy_from_slice(buf);
                platform::write_at(&self.file, offset, scratch.as_slice())
            } else {
                let unbuffered = std::fs::OpenOptions::new().write(true).open(&self.path)?;
                platform::write_at(&unbuffered, offset, buf)
            }
        } else {
            platform::write_at(&self.file, offset, buf)
        }
    }

    /// Read exactly `buf.len()` bytes at `offset`, looping over short
    /// reads. Errors with `UnexpectedEof` if the file ends first.
    pub fn read_at_exact(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(offset, buf)? {
                0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                n => {
                    offset += n as u64;
                    buf = &mut buf[n..];
                }
            }
        }
        Ok(())
    }

    /// Write all of `buf` at `offset`, looping over short writes.
    pub fn write_at_exact(&self, mut offset: u64, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write_at(offset, buf)? {
                0 => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                n => {
                    offset += n as u64;
                    buf = &buf[n..];
                }
            }
        }
        Ok(())
    }

    /// Set the file's length. On filesystems that support sparse
    /// files, extending via `set_len` creates a hole rather than
    /// materializing zero bytes — the write strategy this tool uses
    /// for the padding region beyond `input_len` so nothing ever
    /// accidentally routes through the cipher.
    pub fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Create (or truncate) `path` and pre-size it to `len` bytes via
/// `set_len`, for the sparse-hole padding-region strategy.
pub fn create_sparse_output(path: &Path, len: u64) -> io::Result<SectorFile> {
    let sf = SectorFile::open_write(path, true)?;
    sf.set_len(len)?;
    Ok(sf)
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    use std::path::Path;

    pub fn open_read(path: &Path) -> io::Result<(File, bool)> {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(path)
        {
            Ok(f) => Ok((f, true)),
            Err(_) => Ok((OpenOptions::new().read(true).open(path)?, false)),
        }
    }

    pub fn open_write(path: &Path, create: bool) -> io::Result<(File, bool)> {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .custom_flags(libc::O_DIRECT)
            .open(path)
        {
            Ok(f) => Ok((f, true)),
            Err(_) => Ok((
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(create)
                    .open(path)?,
                false,
            )),
        }
    }

    pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.read_at(buf, offset)
    }

    pub fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<usize> {
        file.write_at(buf, offset)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    pub fn open_read(path: &Path) -> io::Result<(File, bool)> {
        Ok((OpenOptions::new().read(true).open(path)?, false))
    }

    pub fn open_write(path: &Path, create: bool) -> io::Result<(File, bool)> {
        Ok((
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .open(path)?,
            false,
        ))
    }

    pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.read_at(buf, offset)
    }

    pub fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<usize> {
        file.write_at(buf, offset)
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::FileExt;
    use std::path::Path;

    pub fn open_read(path: &Path) -> io::Result<(File, bool)> {
        Ok((OpenOptions::new().read(true).open(path)?, false))
    }

    pub fn open_write(path: &Path, create: bool) -> io::Result<(File, bool)> {
        Ok((
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .open(path)?,
            false,
        ))
    }

    pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.seek_read(buf, offset)
    }

    pub fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<usize> {
        file.seek_write(buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nocap-crypt-blockio-test-{}-{}",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn write_then_read_at_offset_roundtrips() {
        // A whole-sector, sector-aligned transfer — the only shape
        // `SectorFile` is ever actually used with in this project.
        // O_DIRECT (when active) requires the transfer *length*, not
        // just the buffer's memory address, to be block-size-aligned;
        // a short, arbitrary-length transfer fails with EINVAL on a
        // real O_DIRECT-backed filesystem regardless of buffer
        // alignment (`temp_dir()` landing on tmpfs, which doesn't
        // support O_DIRECT at all, won't catch this).
        let path = temp_path("rw");
        let sf = SectorFile::open_write(&path, true).unwrap();
        sf.set_len(4096).unwrap();
        let pattern: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        sf.write_at_exact(512, &pattern).unwrap();

        let mut buf = [0u8; 512];
        sf.read_at_exact(512, &mut buf).unwrap();
        assert_eq!(&buf[..], pattern.as_slice());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sparse_output_has_requested_length() {
        let path = temp_path("sparse");
        let sf = create_sparse_output(&path, 1_048_576).unwrap();
        assert_eq!(sf.len().unwrap(), 1_048_576);
        assert!(!sf.is_empty().unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn zero_length_output_is_empty() {
        let path = temp_path("empty");
        let sf = create_sparse_output(&path, 0).unwrap();
        assert!(sf.is_empty().unwrap());
        std::fs::remove_file(&path).ok();
    }

    /// Regression test for a real bug: `write_at`'s O_DIRECT scratch
    /// buffer was sized to `buf.len()` exactly instead of rounded up
    /// like `read_at`'s, so a non-`DIRECT_IO_ALIGNMENT`-multiple write
    /// (the tail range of any file whose length isn't a whole number
    /// of 4096-byte chunks — routine for real dm-crypt `plain` volumes,
    /// which only need 512-byte alignment) would hit the kernel's
    /// O_DIRECT length check directly. Only meaningfully exercises the
    /// O_DIRECT path on Linux with a filesystem that actually supports
    /// it (this repo's temp dir on tmpfs falls back to buffered I/O,
    /// same caveat as `write_then_read_at_offset_roundtrips` above) —
    /// still asserts the correct byte-for-byte result either way.
    #[test]
    fn write_at_non_aligned_tail_length_roundtrips() {
        let path = temp_path("tail");
        let sf = SectorFile::open_write(&path, true).unwrap();
        sf.set_len(4608).unwrap(); // 4096 + 512: one aligned chunk + a short tail
        let head: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let tail: Vec<u8> = (0..512u32).map(|i| ((i * 3) % 256) as u8).collect();
        sf.write_at_exact(0, &head).unwrap();
        sf.write_at_exact(4096, &tail).unwrap();

        assert_eq!(
            sf.len().unwrap(),
            4608,
            "tail write must not extend the file past its set length"
        );

        let mut readback = vec![0u8; 4608];
        sf.read_at_exact(0, &mut readback).unwrap();
        assert_eq!(&readback[..4096], head.as_slice());
        assert_eq!(&readback[4096..], tail.as_slice());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_past_eof_errors() {
        let path = temp_path("eof");
        let sf = SectorFile::open_write(&path, true).unwrap();
        sf.set_len(16).unwrap();
        let mut buf = [0u8; 32];
        assert!(sf.read_at_exact(0, &mut buf).is_err());
        std::fs::remove_file(&path).ok();
    }
}
