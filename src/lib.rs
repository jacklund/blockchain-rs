extern crate byteorder;
extern crate merkle;
extern crate ring;
extern crate time;

use byteorder::{LittleEndian, WriteBytesExt};
use ring::digest::SHA256;
use std::io::{self, Write};

pub trait Serializable {
    fn serialize(&self) -> Result<Vec<u8>, io::Error>;
}

pub struct Block<T: Serializable + Clone> {
    version: u32,
    previous_hash: Vec<u8>,
    merkle_root_hash: Vec<u8>,
    timestamp: u32,
    n_bits: u32,
    nonce: u32,
    data: Vec<T>,
}

impl <T: Serializable + Clone> Block<T> {
    pub fn new(version: u32, previous_hash: Vec<u8>, values: &[T], n_bits: u32) -> Result<Block<T>, io::Error> {
        let now = time::now().to_timespec().sec as u32;

        let mut data: Vec<Vec<u8>> = Vec::new();
        for value in values {
            data.push(value.serialize()?);
        }
        let merkle = calculate_merkle(&data);

        Ok(Block {
            version: version,
            previous_hash: previous_hash,
            merkle_root_hash: merkle,
            timestamp: now,
            n_bits: n_bits,
            nonce: 0,
            data: values.to_vec(),
        })
    }

    pub fn set_nonce(&mut self, nonce: u32) {
        self.nonce = nonce;
    }

    pub fn hash(&self) -> Result<ring::digest::Digest, io::Error> {
        Ok(ring::digest::digest(&ring::digest::SHA256, self.serialize()?.as_slice()))
    }
}

impl <T: Serializable + Clone> Serializable for Block<T> {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u32::<LittleEndian>(self.version)?;
        buffer.write_all(self.previous_hash.as_slice())?;
        buffer.write_all(self.merkle_root_hash.as_slice())?;
        buffer.write_u32::<LittleEndian>(self.timestamp)?;
        buffer.write_u32::<LittleEndian>(self.n_bits)?;
        buffer.write_all(compact_size_of(self.data.len() as u64)?.as_slice())?;

        Ok(buffer)
    }
}

fn calculate_merkle(data: &[Vec<u8>]) -> Vec<u8> {
    merkle::MerkleTree::from_vec(&SHA256, data.to_vec().clone()).root_hash().clone()
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
