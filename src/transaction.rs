use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};
use util::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Outpoint {
    hash: [u8; 32],
    index: u32,
}

impl Serializable for Outpoint {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_all(&self.hash)?;
        buffer.write_u32::<LittleEndian>(self.index)?;

        Ok(buffer)
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let mut hash: [u8; 32] = [0; 32];
        reader.read_exact(&mut hash)?;
        let index = reader.read_u32::<LittleEndian>()?;

        Ok(Outpoint {
               hash: hash,
               index: index,
           })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Input {
    prev_hash: Outpoint,
    txin_script: Vec<u8>,
    sequence_no: u32,
}

impl Input {
    pub fn new(prev_hash: &[u8; 32], prev_seq: u32, script: &[u8], sequence_no: u32) -> Input {
        Input {
            prev_hash: Outpoint {
                hash: *prev_hash,
                index: prev_seq,
            },
            txin_script: script.to_vec(),
            sequence_no: sequence_no,
        }
    }
}

impl Serializable for Input {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_all(&self.prev_hash.serialize()?)?;
        buffer
            .write_all(VarInt(self.txin_script.len() as u64)
                           .serialize()?
                           .as_slice())?;
        buffer.write_all(self.txin_script.as_slice())?;
        buffer.write_u32::<LittleEndian>(self.sequence_no)?;

        Ok(buffer)
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let prev_hash = Outpoint::deserialize(reader)?;
        let txin_script_length = VarInt::deserialize(reader)?;
        println!("txin script length = {}", txin_script_length.0);
        let mut txin_script = vec![0; txin_script_length.0 as usize];
        reader.read_exact(txin_script.as_mut_slice())?;
        let sequence_no = reader.read_u32::<LittleEndian>()?;

        Ok(Input {
               prev_hash: prev_hash,
               txin_script: txin_script,
               sequence_no: sequence_no,
           })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    value: u64,
    txout_script: Vec<u8>,
}

impl Output {
    pub fn new(value: u64, script: &[u8]) -> Output {
        Output {
            value: value,
            txout_script: script.to_vec(),
        }
    }
}

impl Serializable for Output {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u64::<LittleEndian>(self.value)?;
        buffer
            .write_all(VarInt(self.txout_script.len() as u64)
                           .serialize()?
                           .as_slice())?;
        buffer.write_all(self.txout_script.as_slice())?;

        Ok(buffer)
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let value = reader.read_u64::<LittleEndian>()?;
        let txout_script_length = VarInt::deserialize(reader)?;
        let mut txout_script = vec![0; txout_script_length.0 as usize];
        reader.read_exact(txout_script.as_mut_slice())?;
        Ok(Output {
               value: value,
               txout_script: txout_script,
           })
    }
}

#[derive(Debug, PartialEq)]
pub struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    lock_time: u32,
}

impl Transaction {
    pub fn new(version: u32, inputs: &[Input], outputs: &[Output], lock_time: u32) -> Transaction {
        Transaction {
            version: version,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            lock_time: lock_time,
        }
    }
}

impl Serializable for Transaction {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.write_u32::<LittleEndian>(self.version)?;
        buffer
            .write_all(VarInt(self.inputs.len() as u64).serialize()?.as_slice())?;
        for input in &self.inputs {
            buffer.write_all(input.serialize()?.as_slice())?;
        }
        buffer
            .write_all(VarInt(self.outputs.len() as u64)
                           .serialize()?
                           .as_slice())?;
        for output in &self.outputs {
            buffer.write_all(output.serialize()?.as_slice())?;
        }
        buffer.write_u32::<LittleEndian>(self.lock_time)?;

        Ok(buffer)
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let version = reader.read_u32::<LittleEndian>()?;
        let input_length = VarInt::deserialize(reader)?;
        let mut inputs: Vec<Input> = Vec::new();
        for _ in 0..input_length.0 {
            inputs.push(Input::deserialize(reader)?);
        }
        let output_length = VarInt::deserialize(reader)?;
        let mut outputs: Vec<Output> = Vec::new();
        for _ in 0..output_length.0 {
            outputs.push(Output::deserialize(reader)?);
        }
        let lock_time = reader.read_u32::<LittleEndian>()?;

        Ok(Transaction {
               version: version,
               inputs: inputs,
               outputs: outputs,
               lock_time: lock_time,
           })
    }
}

mod test {
    use super::*;

    #[test]
    fn test_input_serialization() {
        let mut serialized =
            vec![0x6D, 0xBD, 0xDB, 0x08, 0x5B, 0x1D, 0x8A, 0xF7, 0x51, 0x84, 0xF0, 0xBC, 0x01,
                 0xFA, 0xD5, 0x8D, 0x12, 0x66, 0xE9, 0xB6, 0x3B, 0x50, 0x88, 0x19, 0x90, 0xE4,
                 0xB4, 0x0D, 0x6A, 0xEE, 0x36, 0x29, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x48, 0x30,
                 0x45, 0x02, 0x21, 0x00, 0xF3, 0x58, 0x1E, 0x19, 0x72, 0xAE, 0x8A, 0xC7, 0xC7,
                 0x36, 0x7A, 0x7A, 0x25, 0x3B, 0xC1, 0x13, 0x52, 0x23, 0xAD, 0xB9, 0xA4, 0x68,
                 0xBB, 0x3A, 0x59, 0x23, 0x3F, 0x45, 0xBC, 0x57, 0x83, 0x80, 0x02, 0x20, 0x59,
                 0xAF, 0x01, 0xCA, 0x17, 0xD0, 0x0E, 0x41, 0x83, 0x7A, 0x1D, 0x58, 0xE9, 0x7A,
                 0xA3, 0x1B, 0xAE, 0x58, 0x4E, 0xDE, 0xC2, 0x8D, 0x35, 0xBD, 0x96, 0x92, 0x36,
                 0x90, 0x91, 0x3B, 0xAE, 0x9A, 0x01, 0x41, 0x04, 0x9C, 0x02, 0xBF, 0xC9, 0x7E,
                 0xF2, 0x36, 0xCE, 0x6D, 0x8F, 0xE5, 0xD9, 0x40, 0x13, 0xC7, 0x21, 0xE9, 0x15,
                 0x98, 0x2A, 0xCD, 0x2B, 0x12, 0xB6, 0x5D, 0x9B, 0x7D, 0x59, 0xE2, 0x0A, 0x84,
                 0x20, 0x05, 0xF8, 0xFC, 0x4E, 0x02, 0x53, 0x2E, 0x87, 0x3D, 0x37, 0xB9, 0x6F,
                 0x09, 0xD6, 0xD4, 0x51, 0x1A, 0xDA, 0x8F, 0x14, 0x04, 0x2F, 0x46, 0x61, 0x4A,
                 0x4C, 0x70, 0xC0, 0xF1, 0x4B, 0xEF, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF];

        let prev_hash = [0x6D, 0xBD, 0xDB, 0x08, 0x5B, 0x1D, 0x8A, 0xF7, 0x51, 0x84, 0xF0, 0xBC,
                         0x01, 0xFA, 0xD5, 0x8D, 0x12, 0x66, 0xE9, 0xB6, 0x3B, 0x50, 0x88, 0x19,
                         0x90, 0xE4, 0xB4, 0x0D, 0x6A, 0xEE, 0x36, 0x29];

        let script = vec![0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0xF3, 0x58, 0x1E, 0x19, 0x72, 0xAE,
                          0x8A, 0xC7, 0xC7, 0x36, 0x7A, 0x7A, 0x25, 0x3B, 0xC1, 0x13, 0x52, 0x23,
                          0xAD, 0xB9, 0xA4, 0x68, 0xBB, 0x3A, 0x59, 0x23, 0x3F, 0x45, 0xBC, 0x57,
                          0x83, 0x80, 0x02, 0x20, 0x59, 0xAF, 0x01, 0xCA, 0x17, 0xD0, 0x0E, 0x41,
                          0x83, 0x7A, 0x1D, 0x58, 0xE9, 0x7A, 0xA3, 0x1B, 0xAE, 0x58, 0x4E, 0xDE,
                          0xC2, 0x8D, 0x35, 0xBD, 0x96, 0x92, 0x36, 0x90, 0x91, 0x3B, 0xAE, 0x9A,
                          0x01, 0x41, 0x04, 0x9C, 0x02, 0xBF, 0xC9, 0x7E, 0xF2, 0x36, 0xCE, 0x6D,
                          0x8F, 0xE5, 0xD9, 0x40, 0x13, 0xC7, 0x21, 0xE9, 0x15, 0x98, 0x2A, 0xCD,
                          0x2B, 0x12, 0xB6, 0x5D, 0x9B, 0x7D, 0x59, 0xE2, 0x0A, 0x84, 0x20, 0x05,
                          0xF8, 0xFC, 0x4E, 0x02, 0x53, 0x2E, 0x87, 0x3D, 0x37, 0xB9, 0x6F, 0x09,
                          0xD6, 0xD4, 0x51, 0x1A, 0xDA, 0x8F, 0x14, 0x04, 0x2F, 0x46, 0x61, 0x4A,
                          0x4C, 0x70, 0xC0, 0xF1, 0x4B, 0xEF, 0xF5];

        let input = Input::new(&prev_hash, 0, &script, 4294967295);
        assert_eq!(serialized, input.serialize().unwrap());
        assert_eq!(input,
                   Input::deserialize(&mut serialized.as_slice()).unwrap());
    }

    #[test]
    fn test_output_serialization() {
        let serialized = vec![0x40, 0x4B, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xA9,
                              0x14, 0x1A, 0xA0, 0xCD, 0x1C, 0xBE, 0xA6, 0xE7, 0x45, 0x8A, 0x7A,
                              0xBA, 0xD5, 0x12, 0xA9, 0xD9, 0xEA, 0x1A, 0xFB, 0x22, 0x5E, 0x88,
                              0xAC];

        let script = vec![0x76, 0xA9, 0x14, 0x1A, 0xA0, 0xCD, 0x1C, 0xBE, 0xA6, 0xE7, 0x45, 0x8A,
                          0x7A, 0xBA, 0xD5, 0x12, 0xA9, 0xD9, 0xEA, 0x1A, 0xFB, 0x22, 0x5E, 0x88,
                          0xAC];

        let output = Output::new(5000000, &script);

        assert_eq!(serialized, output.serialize().unwrap());
        assert_eq!(output,
                   Output::deserialize(&mut serialized.as_slice()).unwrap());
    }

    #[test]
    fn test_transaction_serialization() {
        let serialized =
            vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x6D, 0xBD, 0xDB, 0x08, 0x5B, 0x1D, 0x8A, 0xF7,
                 0x51, 0x84, 0xF0, 0xBC, 0x01, 0xFA, 0xD5, 0x8D, 0x12, 0x66, 0xE9, 0xB6, 0x3B,
                 0x50, 0x88, 0x19, 0x90, 0xE4, 0xB4, 0x0D, 0x6A, 0xEE, 0x36, 0x29, 0x00, 0x00,
                 0x00, 0x00, 0x8B, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0xF3, 0x58, 0x1E, 0x19,
                 0x72, 0xAE, 0x8A, 0xC7, 0xC7, 0x36, 0x7A, 0x7A, 0x25, 0x3B, 0xC1, 0x13, 0x52,
                 0x23, 0xAD, 0xB9, 0xA4, 0x68, 0xBB, 0x3A, 0x59, 0x23, 0x3F, 0x45, 0xBC, 0x57,
                 0x83, 0x80, 0x02, 0x20, 0x59, 0xAF, 0x01, 0xCA, 0x17, 0xD0, 0x0E, 0x41, 0x83,
                 0x7A, 0x1D, 0x58, 0xE9, 0x7A, 0xA3, 0x1B, 0xAE, 0x58, 0x4E, 0xDE, 0xC2, 0x8D,
                 0x35, 0xBD, 0x96, 0x92, 0x36, 0x90, 0x91, 0x3B, 0xAE, 0x9A, 0x01, 0x41, 0x04,
                 0x9C, 0x02, 0xBF, 0xC9, 0x7E, 0xF2, 0x36, 0xCE, 0x6D, 0x8F, 0xE5, 0xD9, 0x40,
                 0x13, 0xC7, 0x21, 0xE9, 0x15, 0x98, 0x2A, 0xCD, 0x2B, 0x12, 0xB6, 0x5D, 0x9B,
                 0x7D, 0x59, 0xE2, 0x0A, 0x84, 0x20, 0x05, 0xF8, 0xFC, 0x4E, 0x02, 0x53, 0x2E,
                 0x87, 0x3D, 0x37, 0xB9, 0x6F, 0x09, 0xD6, 0xD4, 0x51, 0x1A, 0xDA, 0x8F, 0x14,
                 0x04, 0x2F, 0x46, 0x61, 0x4A, 0x4C, 0x70, 0xC0, 0xF1, 0x4B, 0xEF, 0xF5, 0xFF,
                 0xFF, 0xFF, 0xFF, 0x02, 0x40, 0x4B, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
                 0x76, 0xA9, 0x14, 0x1A, 0xA0, 0xCD, 0x1C, 0xBE, 0xA6, 0xE7, 0x45, 0x8A, 0x7A,
                 0xBA, 0xD5, 0x12, 0xA9, 0xD9, 0xEA, 0x1A, 0xFB, 0x22, 0x5E, 0x88, 0xAC, 0x80,
                 0xFA, 0xE9, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xA9, 0x14, 0x0E, 0xAB,
                 0x5B, 0xEA, 0x43, 0x6A, 0x04, 0x84, 0xCF, 0xAB, 0x12, 0x48, 0x5E, 0xFD, 0xA0,
                 0xB7, 0x8B, 0x4E, 0xCC, 0x52, 0x88, 0xAC, 0x00, 0x00, 0x00, 0x00];

        let prev_hash = [0x6D, 0xBD, 0xDB, 0x08, 0x5B, 0x1D, 0x8A, 0xF7, 0x51, 0x84, 0xF0, 0xBC,
                         0x01, 0xFA, 0xD5, 0x8D, 0x12, 0x66, 0xE9, 0xB6, 0x3B, 0x50, 0x88, 0x19,
                         0x90, 0xE4, 0xB4, 0x0D, 0x6A, 0xEE, 0x36, 0x29];

        let input_script =
            vec![0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0xF3, 0x58, 0x1E, 0x19, 0x72, 0xAE, 0x8A,
                 0xC7, 0xC7, 0x36, 0x7A, 0x7A, 0x25, 0x3B, 0xC1, 0x13, 0x52, 0x23, 0xAD, 0xB9,
                 0xA4, 0x68, 0xBB, 0x3A, 0x59, 0x23, 0x3F, 0x45, 0xBC, 0x57, 0x83, 0x80, 0x02,
                 0x20, 0x59, 0xAF, 0x01, 0xCA, 0x17, 0xD0, 0x0E, 0x41, 0x83, 0x7A, 0x1D, 0x58,
                 0xE9, 0x7A, 0xA3, 0x1B, 0xAE, 0x58, 0x4E, 0xDE, 0xC2, 0x8D, 0x35, 0xBD, 0x96,
                 0x92, 0x36, 0x90, 0x91, 0x3B, 0xAE, 0x9A, 0x01, 0x41, 0x04, 0x9C, 0x02, 0xBF,
                 0xC9, 0x7E, 0xF2, 0x36, 0xCE, 0x6D, 0x8F, 0xE5, 0xD9, 0x40, 0x13, 0xC7, 0x21,
                 0xE9, 0x15, 0x98, 0x2A, 0xCD, 0x2B, 0x12, 0xB6, 0x5D, 0x9B, 0x7D, 0x59, 0xE2,
                 0x0A, 0x84, 0x20, 0x05, 0xF8, 0xFC, 0x4E, 0x02, 0x53, 0x2E, 0x87, 0x3D, 0x37,
                 0xB9, 0x6F, 0x09, 0xD6, 0xD4, 0x51, 0x1A, 0xDA, 0x8F, 0x14, 0x04, 0x2F, 0x46,
                 0x61, 0x4A, 0x4C, 0x70, 0xC0, 0xF1, 0x4B, 0xEF, 0xF5];

        let output_script_1 = vec![0x76, 0xA9, 0x14, 0x1A, 0xA0, 0xCD, 0x1C, 0xBE, 0xA6, 0xE7,
                                   0x45, 0x8A, 0x7A, 0xBA, 0xD5, 0x12, 0xA9, 0xD9, 0xEA, 0x1A,
                                   0xFB, 0x22, 0x5E, 0x88, 0xAC];

        let output_script_2 = vec![0x76, 0xA9, 0x14, 0x0E, 0xAB, 0x5B, 0xEA, 0x43, 0x6A, 0x04,
                                   0x84, 0xCF, 0xAB, 0x12, 0x48, 0x5E, 0xFD, 0xA0, 0xB7, 0x8B,
                                   0x4E, 0xCC, 0x52, 0x88, 0xAC];

        let input = Input::new(&prev_hash, 0, &input_script, 4294967295);

        let output_1 = Output::new(5000000, &output_script_1);
        let output_2 = Output::new(3354000000, &output_script_2);

        let transaction = Transaction::new(1, &[input], &[output_1, output_2], 0);

        let mine = transaction.serialize().unwrap();

        assert_eq!(serialized, transaction.serialize().unwrap());
        assert_eq!(transaction, Transaction::deserialize(&mut serialized.as_slice()).unwrap());
    }
}
