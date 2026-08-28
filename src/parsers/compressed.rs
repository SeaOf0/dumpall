use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;

use crate::error::Result;

/// gzip 解压输出硬上限(2GB):压缩后体积小、解压后巨大的"解压炸弹"日志
/// 不能无上限地流入内存;超限由上层降级为该文件的 ParseError 记录。
pub(crate) const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// 打开日志读取器;`max_decompressed_bytes` 为 gzip 解压侧累计输出上限
/// (调用方传入 max_file_size,内部再与 2GB 硬上限取小)。
pub fn open_log_reader(path: &Path, max_decompressed_bytes: u64) -> Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    let reader: Box<dyn Read> = if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("gz"))
        .unwrap_or(false)
    {
        let cap = max_decompressed_bytes.min(MAX_DECOMPRESSED_BYTES);
        Box::new(GzDecoder::new(LimitedReader::new(file, cap)))
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::new(reader)))
}

/// 限制累计读取字节数的包装读取器:超出上限返回 InvalidData,
/// 内存峰值受控,错误可被上层识别并转为 ParseError。
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed stream exceeds cap",
            ));
        }
        let limit = self.remaining.min(buf.len() as u64) as usize;
        let read = self.inner.read(&mut buf[..limit])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn limited_reader_stops_at_cap() {
        let data = vec![b'a'; 64];
        let mut reader = LimitedReader::new(Cursor::new(data), 16);
        let mut buffer = [0u8; 8];
        // 前 16 字节正常读出
        assert_eq!(reader.read(&mut buffer).unwrap(), 8);
        assert_eq!(reader.read(&mut buffer).unwrap(), 8);
        // 超过上限后返回 InvalidData 而不是继续输出
        let error = reader.read(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds cap"));
    }
}
