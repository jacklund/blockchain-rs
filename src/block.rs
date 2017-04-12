
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};
use time;
use util::*;

const BLOCK_MAGIC_NUMBER: u32 = 0xD9B4BEF9;

pub struct BlockHeader {
    version: u32,
    previous_hash: Vec<u8>,
    merkle_root_hash: Vec<u8>,
    timestamp: u32,
    bits: u32,
    nonce: u32,
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
        buffer.write_all(VarInt(self.data.len() as u64).serialize()?.as_slice());
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
        let data_size = VarInt::deserialize(buffer.as_slice())?;
        let mut data: Vec<T> = Vec::new();
        for _ in 0..data_size.0 {
            data.push(T::deserialize(buffer.as_mut_slice())?);
        }

        Ok(Block {
            header: header,
            data: Vec::new(),
        })
    }
}