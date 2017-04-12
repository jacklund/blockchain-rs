use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ring;
use std;
use std::io::{self, Read};

pub trait Serializable: Sized {
    fn serialize(&self) -> Result<Vec<u8>, io::Error>;

    fn deserialize(buffer: &[u8]) -> Result<Self, io::Error>;
}

pub fn single_hash(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut buffer: Vec<u8> = Vec::new();
    digest.as_ref().read_to_end(&mut buffer)?;

    Ok(buffer)
}

pub fn double_hash(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    Ok(single_hash(single_hash(data)?.as_slice())?)
}

fn concat_and_hash(values: &[Vec<u8>]) -> Result<Vec<u8>, io::Error> {
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
        concat_and_hash(&hashes)
    }
}

pub fn calculate_merkle(data: &[Vec<u8>]) -> Result<Vec<u8>, io::Error> {
    if data.is_empty() {
        return Ok(double_hash(&[])?);
    }
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for value in data {
        hashes.push(double_hash(value.as_slice())?);
    }
    concat_and_hash(&hashes)
}

pub struct VarInt(pub u64);

impl Serializable for VarInt {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        let value = self.0;
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

    fn deserialize(mut buffer: &[u8]) -> Result<Self, io::Error> {
        let first_byte = buffer.read_u8()?;
        let value: u64 = match first_byte {
            0xfd => buffer.read_u16::<LittleEndian>()? as u64,
            0xfe => buffer.read_u32::<LittleEndian>()? as u64,
            0xff => buffer.read_u64::<LittleEndian>()?,
            _ => first_byte as u64,
        };

        Ok(VarInt(value))
    }
}