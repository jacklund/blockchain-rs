#![feature(box_syntax)]

extern crate byteorder;
extern crate merkle;
extern crate ring;
extern crate time;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

const BLOCK_MAGIC_NUMBER: u32 = 0xD9B4BEF9;

pub trait Serializable: Sized {
    fn serialize(&self) -> Result<Vec<u8>, io::Error>;

    fn deserialize(buffer: &[u8]) -> Result<Self, io::Error>;
}

pub struct BlockHeader {
    version: u32,
    previous_hash: Vec<u8>,
    merkle_root_hash: Vec<u8>,
    timestamp: u32,
    bits: u32,
    nonce: u32,
}

fn single_hash(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut buffer: Vec<u8> = Vec::new();
    digest.as_ref().read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn double_hash(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    Ok(single_hash(single_hash(data)?.as_slice())?)
}

impl BlockHeader {
    pub fn hash(&self) -> Result<Vec<u8>, io::Error> {
        Ok(double_hash(self.serialize()?.as_slice())?)
    }
}

impl Serializable for BlockHeader {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u32::<LittleEndian>(self.version)?;
        buffer.write_all(self.previous_hash.as_slice())?;
        buffer.write_all(self.merkle_root_hash.as_slice())?;
        buffer.write_u32::<LittleEndian>(self.timestamp)?;
        buffer.write_u32::<LittleEndian>(self.bits)?;
        buffer.write_u32::<LittleEndian>(self.nonce)?;

        Ok(buffer)
    }

    fn deserialize(mut buffer: &[u8]) -> Result<BlockHeader, io::Error> {
        let version = buffer.read_u32::<LittleEndian>()?;
        let mut previous_hash = vec![0; 32];
        buffer.read_exact(previous_hash.as_mut_slice())?;
        let mut merkle_root_hash = vec![0; 32];
        buffer.read_exact(merkle_root_hash.as_mut_slice())?;
        let timestamp = buffer.read_u32::<LittleEndian>()?;
        let bits = buffer.read_u32::<LittleEndian>()?;
        let nonce = buffer.read_u32::<LittleEndian>()?;

        Ok(BlockHeader {
            version: version,
            previous_hash: previous_hash,
            merkle_root_hash: merkle_root_hash,
            timestamp: timestamp,
            bits: bits,
            nonce: nonce,
        })
    }
}

pub struct Block<T: Serializable + Clone> {
    header: BlockHeader,
    data: Vec<T>,
}

impl<T: Serializable + Clone> Block<T> {
    pub fn new(version: u32,
               previous_hash: Vec<u8>,
               values: &[T],
               bits: u32)
               -> Result<Block<T>, io::Error> {
        let now = time::now().to_timespec().sec as u32;

        let mut data: Vec<Vec<u8>> = Vec::new();
        for value in values {
            data.push(value.serialize()?);
        }
        let merkle = calculate_merkle(&data)?;

        Ok(Block {
            header: BlockHeader {
                version: version,
                previous_hash: previous_hash,
                merkle_root_hash: merkle,
                timestamp: now,
                bits: bits,
                nonce: 0,
            },
            data: values.to_vec(),
        })
    }

    pub fn set_nonce(&mut self, nonce: u32) {
        self.header.nonce = nonce;
    }

    pub fn header_hash(&self) -> Result<Vec<u8>, io::Error> {
        self.header.hash()
    }
}

impl<T: Serializable + Clone> Serializable for Block<T> {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u32::<LittleEndian>(BLOCK_MAGIC_NUMBER)?;
        buffer.write_u32::<LittleEndian>(0)?;
        buffer.write_all(self.header.serialize()?.as_ref())?;
        buffer.write_all(compact_size_of(self.data.len() as u64)?.as_slice())?;
        for item in self.data.iter() {
            buffer.write_all(item.serialize()?.as_ref())?;
        }

        let size: u32 = buffer.len() as u32 - 8;
        {
            let mut slice = buffer.get_mut(4..8).unwrap();
            slice.write_u32::<LittleEndian>(size)?;
        }

        Ok(buffer)
    }

    fn deserialize(mut data: &[u8]) -> Result<Block<T>, io::Error> {
        let magic = data.read_u32::<LittleEndian>()?;
        if magic != BLOCK_MAGIC_NUMBER {
            // TODO: Replace with actual error
            panic!("Bad block header found: {:?}", magic);
        }
        let size = data.read_u32::<LittleEndian>()?;
        let mut buffer = vec![0; size as usize];
        data.read_exact(buffer.as_mut_slice())?;

        let header = BlockHeader::deserialize(buffer.as_mut_slice())?;
        let data_size = read_compact_size(buffer.as_slice())?;
        let mut data: Vec<T> = Vec::new();
        for _ in 0..data_size {
            data.push(T::deserialize(buffer.as_mut_slice())?);
        }

        Ok(Block {
            header: header,
            data: Vec::new(),
        })
    }
}

fn concat_and_hash(values: Vec<Vec<u8>>) -> Result<Vec<u8>, io::Error> {
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for chunk in values.chunks(2) {
        let mut first = chunk[0].clone();
        if chunk.len() == 2 {
            first.extend(chunk[1].iter());
        } else {
            first.extend(chunk[0].iter());
        }
        hashes.push(double_hash(first.as_slice())?);
    }

    if hashes.len() == 1 {
        Ok(hashes[0].clone())
    } else {
        concat_and_hash(hashes)
    }
}

fn calculate_merkle(data: &[Vec<u8>]) -> Result<Vec<u8>, io::Error> {
    if data.is_empty() {
        return Ok(double_hash(&[])?)
    }
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for value in data {
        hashes.push(double_hash(value.as_slice())?);
    }
    concat_and_hash(hashes)
}

fn compact_size_of(value: u64) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    if value <= 252 {
        buffer.write_u8(value as u8)?;
    } else if value <= std::u16::MAX as u64 {
        buffer.write_u8(0xfd)?;
        buffer.write_u16::<LittleEndian>(value as u16)?;
    } else if value <= std::u32::MAX as u64 {
        buffer.write_u8(0xfe)?;
        buffer.write_u32::<LittleEndian>(value as u32)?;
    } else {
        buffer.write_u8(0xff)?;
        buffer.write_u64::<LittleEndian>(value)?;
    }

    Ok(buffer)
}

fn read_compact_size(mut buffer: &[u8]) -> Result<u64, io::Error> {
    let first_byte = buffer.read_u8()?;
    let value: u64 = match first_byte {
        0xfd => buffer.read_u16::<LittleEndian>()? as u64,
        0xfe => buffer.read_u32::<LittleEndian>()? as u64,
        0xff => buffer.read_u64::<LittleEndian>()?,
        _ => first_byte as u64,
    };

    Ok(value)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
