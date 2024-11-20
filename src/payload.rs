use std::{error::Error, fs::File, io::{self, BufReader, Read, Seek, SeekFrom}, str};
use bzip2::read::BzDecoder;
use liblzma::bufread::XzDecoder;
use std::fmt::Write;
use sha2::{Digest, Sha256};

use crate::chromeos_update_engine::{install_operation::Type, DeltaArchiveManifest, PartitionUpdate};

const PAYLOAD_HEADER_MAGIC: &str = "CrAU";
const BRILLO_MAJOR_PAYLOAD_VERSION: u64 = 2;
const BLOCK_SIZE: u64 = 4096;

pub struct Payload {
    path: String,
    file: File,
    header: Option<PayloadHeader>,
    manifest: Option<DeltaArchiveManifest>
}

pub struct PayloadHeader {
    version: u64,
    size: u64,
    manifest_len: u64,
    signature_len: u32,
    data_offset: u64,
    metadata_size: u64
}

impl Payload {
    pub fn new(path: String) -> Result<Self, Box<dyn Error>> {
        let file = File::open(&path).map_err(|err| format!("File open error: {}", err))?;
        Ok(Self { path, file, header: None, manifest: None })
    }

    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        self.header = Some(self.read_header()?);
        self.manifest = Some(self.read_manifest()?);
        Ok(())
    }

    fn read_header(&mut self) -> Result<PayloadHeader, Box<dyn Error>> {
        let mut buf = [0; 4];
        self.file.read_exact(&mut buf)?;
        if str::from_utf8(&buf)? != PAYLOAD_HEADER_MAGIC {
            return Err("Invalid Payload magic".into());
        }

        let mut header = PayloadHeader {
            version: self.read_u64()?,
            manifest_len: self.read_u64()?,
            signature_len: self.read_u32()?,
            size: 24,
            metadata_size: 0,
            data_offset: 0,
        };

        if header.version != BRILLO_MAJOR_PAYLOAD_VERSION {
            return Err("Unsupported payload version".into());
        }

        header.metadata_size = header.size + header.manifest_len;
        header.data_offset = header.signature_len as u64 + header.metadata_size;

        Ok(header)
    }

    fn read_manifest(&mut self) -> Result<DeltaArchiveManifest, Box<dyn Error>> {
        let manifest_len = self.header.as_ref().ok_or("Missing header")?.manifest_len as usize;
        let mut manifest_buf = vec![0; manifest_len];
        self.file.read_exact(&mut manifest_buf)?;
        Ok(prost::Message::decode(&manifest_buf[..])?)
    }

    pub fn extract<'p>(&mut self, partition_to_extract: &str, out_file: &str, onprpgress: &'p dyn Fn(usize)) -> Result<String, Box<dyn Error>> {
        self.init()?;
        let manifest = self.manifest.as_ref().ok_or("Manifest not initialized")?;

        for partition in manifest.partitions.clone() {
            if partition.partition_name == partition_to_extract {
                self.extract_selected(&partition, out_file, &onprpgress)?;
                return Ok("Done".into());
            }
        }
        Err(format!("Partition {} not found", partition_to_extract).into())
    }


    fn extract_selected<'p>(&mut self, partition: &PartitionUpdate, out_file: &str, onprogress: &'p dyn Fn(usize)) -> Result<(), Box<dyn Error>> {
        let mut output_file = File::create(out_file)
            .map_err(|err| format!("Failed to create output file: {}", err))?;
        let mut reader = BufReader::new(&self.file);

        let mut progress: usize = 0;
        let operation_len = partition.operations.len();

        for operation in &partition.operations {
            let dst = operation.dst_extents.get(0)
                .ok_or("Invalid destination extents in operation")?;
            let data_offset = operation.data_offset
                .ok_or("Missing data offset in operation")? + self.header.as_ref().unwrap().data_offset;
            let data_length = operation.data_length
                .ok_or("Missing data length in operation")?;
            let expected_size = dst.num_blocks() * BLOCK_SIZE;

            reader.seek(SeekFrom::Start(data_offset))?;

            let mut sha = Sha256::new();

            let mut reader = Read::take(&mut reader, data_length);
            let mut buf = vec![0; data_length as usize];
            let _ = reader.read(&mut buf);
            sha.update(&mut buf);

            // println!("Offset: {}, Length: {}", &data_offset, &data_length);
            let mut bytes_written: u64 = 0;
            match operation.r#type() {
                Type::Replace => {
                    bytes_written = io::copy(&mut buf.as_slice(), &mut output_file)?;
                },
                Type::ReplaceXz => {
                    let mut decoder = XzDecoder::new(buf.as_slice());
                    bytes_written = io::copy(&mut decoder, &mut output_file)?;

                },
                Type::ReplaceBz => {
                    bytes_written = io::copy(&mut BzDecoder::new(buf.as_slice()), &mut output_file)?;
                },
                Type::Zero => {
                    bytes_written = io::copy(&mut io::repeat(0).take(expected_size), &mut output_file)?;
                }
                _ => return Err("Unsupported operation type".into()),
            }
            let hash = hex::encode(sha.finalize());
            let hash_expected = hex::encode(operation.data_sha256_hash());
            if bytes_written != expected_size {
                return Err("Unexpected byte written".into());
            }
            if hash != hash_expected {
                println!("hash mismatched{:?}\n{:?}", hash, hash_expected);
                return Err("hash mismatch".into())
            }
						progress += 1;
            onprogress((progress * 100) / operation_len);
        }
        Ok(())
    }

    pub fn get_partition_list(&mut self) -> Result<String, Box<dyn Error>> {
        self.init()?;
        let manifest = self.manifest.as_ref().ok_or("No manifest available")?;
        let mut msg = String::from("Partitions: ");
        for (i, partition) in manifest.partitions.iter().enumerate() {
            let size = partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0);
            write!(msg, "{}|{}", partition.partition_name, size).unwrap();
            if i < manifest.partitions.len() - 1 {
                msg.push_str(", ");
            }
        }
        Ok(msg)
    }

    fn read_u64(&mut self) -> Result<u64, Box<dyn Error>> {
        let mut buf = [0; 8];
        self.file.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32, Box<dyn Error>> {
        let mut buf = [0; 4];
        self.file.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
}
