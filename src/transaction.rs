use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};
use util::*;

pub struct Input {
    prev_hash: Vec<u8>,
    prev_txout_index: u32,
    txin_script: Vec<u8>,
    sequence_no: u32,
}

impl Serializable for Input {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_all(self.prev_hash.as_slice())?;
        buffer.write_u32::<LittleEndian>(self.prev_txout_index)?;
        buffer.write_all(VarInt(self.txin_script.len() as u64).serialize()?.as_slice())?;
        buffer.write_all(self.txin_script.as_slice())?;
        buffer.write_u32::<LittleEndian>(self.sequence_no)?;

        Ok(buffer)
    }

    fn deserialize(mut buffer: &[u8]) -> Result<Self, io::Error> {
        let mut prev_hash = vec![0; 32];
        buffer.read_exact(prev_hash.as_mut_slice())?;
        let prev_txout_index = buffer.read_u32::<LittleEndian>()?;
        let txin_script_length = VarInt::deserialize(buffer)?;
        let mut txin_script = vec![0; txin_script_length.0 as usize];
        buffer.read_exact(txin_script.as_mut_slice())?;
        let sequence_no = buffer.read_u32::<LittleEndian>()?;

        Ok(Input {
            prev_hash: prev_hash,
            prev_txout_index: prev_txout_index,
            txin_script: txin_script,
            sequence_no: sequence_no,
        })
    }
}

pub struct Output {
    value: u64,
    txout_script: Vec<u8>,
}

impl Serializable for Output {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u64::<LittleEndian>(self.value)?;
        buffer.write_all(VarInt(self.txout_script.len() as u64).serialize()?.as_slice())?;
        buffer.write_all(self.txout_script.as_slice())?;

        Ok(buffer)
    }

    fn deserialize(mut buffer: &[u8]) -> Result<Self, io::Error> {
        let value = buffer.read_u64::<LittleEndian>()?;
        let txout_script_length = VarInt::deserialize(buffer)?;
        let mut txout_script = vec![0; txout_script_length.0 as usize];
        buffer.read_exact(txout_script.as_mut_slice())?;
        Ok(Output {
            value: value,
            txout_script: txout_script,
        })
    }
}

pub struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    lock_time: u32,
}

impl Serializable for Transaction {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u32::<LittleEndian>(self.version)?;
        buffer.write_all(VarInt(self.inputs.len() as u64).serialize()?.as_slice())?;
        for input in self.inputs.iter() {
            buffer.write_all(input.serialize()?.as_slice())?;
        }
        buffer.write_all(VarInt(self.outputs.len() as u64).serialize()?.as_slice())?;
        for output in self.outputs.iter() {
            buffer.write_all(output.serialize()?.as_slice())?;
        }
        buffer.write_u32::<LittleEndian>(self.lock_time)?;

        Ok(buffer)
    }

    fn deserialize(mut buffer: &[u8]) -> Result<Self, io::Error> {
        let version = buffer.read_u32::<LittleEndian>()?;
        let input_length = VarInt::deserialize(buffer)?;
        let mut inputs: Vec<Input> = Vec::new();
        for _ in 0..input_length.0 {
            inputs.push(Input::deserialize(buffer)?);
        }
        let output_length = VarInt::deserialize(buffer)?;
        let mut outputs: Vec<Output> = Vec::new();
        for _ in 0..output_length.0 {
            outputs.push(Output::deserialize(buffer)?);
        }
        let lock_time = buffer.read_u32::<LittleEndian>()?;

        Ok(Transaction {
            version: version,
            inputs: inputs,
            outputs: outputs,
            lock_time: lock_time,
        })
    }
}