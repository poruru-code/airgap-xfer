use std::io::{self, BufReader, Read};
use zstd::stream::read::{Decoder, Encoder};

use crate::Error;

pub struct ZstdReader<R: Read> {
    inner: Encoder<'static, BufReader<R>>,
}

impl<R: Read> ZstdReader<R> {
    pub fn new(reader: R, level: i32) -> Result<Self, Error> {
        let inner = Encoder::new(reader, level).map_err(|e| Error::CompressionError {
            message: e.to_string(),
        })?;
        Ok(ZstdReader { inner })
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

pub fn zstd_reader<R: Read>(reader: R, level: i32) -> Result<ZstdReader<R>, Error> {
    ZstdReader::new(reader, level)
}

pub struct ZstdDecoder<R: Read> {
    inner: Decoder<'static, BufReader<R>>,
}

impl<R: Read> ZstdDecoder<R> {
    pub fn new(reader: R) -> Result<Self, Error> {
        let inner = Decoder::new(reader).map_err(|e| Error::CompressionError {
            message: e.to_string(),
        })?;
        Ok(ZstdDecoder { inner })
    }
}

impl<R: Read> Read for ZstdDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

pub fn zstd_decoder<R: Read>(reader: R) -> Result<ZstdDecoder<R>, Error> {
    ZstdDecoder::new(reader)
}
