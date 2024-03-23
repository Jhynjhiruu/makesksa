use anyhow::Result;
use bb::{BbAesIv, BbAesKey};
use clap::Parser;
use clap_num::maybe_hex;
use hex::FromHex;

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs::{read, read_to_string, write};
use std::io::{stdout, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum IOType {
    Stdin,
    Stdout,
    File(PathBuf),
}

impl IOType {
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Stdin => {
                let mut rv = vec![];
                std::io::stdin().lock().read_to_end(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn read_string(&self) -> Result<String, Error> {
        match self {
            Self::Stdin => {
                let mut rv = String::new();
                std::io::stdin().lock().read_to_string(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read_to_string(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn write<T: AsRef<[u8]>>(&self, data: T) -> Result<usize, Error> {
        match self {
            Self::Stdin => Err(Error::from(ErrorKind::Unsupported)),
            Self::Stdout => stdout().write(data.as_ref()),
            Self::File(path) => write(path, &data).and(Ok(data.as_ref().len())),
        }
    }

    fn input<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdin,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn output<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdout,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn derive_input<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdin,
            Self::Stdout => Self::Stdin,
            Self::File(p) => Self::File(f(p)),
        }
    }

    fn derive_output<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdout,
            Self::Stdout => Self::Stdout,
            Self::File(p) => Self::File(f(p)),
        }
    }
}

impl Display for IOType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stdin => "stdin".to_string(),
                Self::Stdout => "stdout".to_string(),
                Self::File(f) => f.display().to_string(),
            }
        )
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input Virage2 (used for key derivation)
    virage2: String,

    /// Input bootrom (used for key derivation)
    bootrom: String,

    /// Input SK
    sk: String,

    /// Input SA1
    sa1: String,

    /// Input SA1 CID
    #[arg(value_parser=maybe_hex::<u32>)]
    sa1_cid: u32,

    /// Input SA1 encryption key (optional)
    #[arg(long)]
    sa1_key: Option<String>,

    /// Input SA1 encryption IV (optional)
    #[arg(long)]
    sa1_iv: Option<String>,

    /// Input SA1 key IV (optional)
    #[arg(long)]
    sa1_key_iv: Option<String>,

    /// Input SA2 (optional)
    #[arg(requires("sa2_cid"))]
    sa2: Option<String>,

    /// Input SA2 CID
    #[arg(value_parser=maybe_hex::<u32>)]
    sa2_cid: Option<u32>,

    /// Input SA2 encryption key (optional)
    #[arg(long, requires("sa2"))]
    sa2_key: Option<String>,

    /// Input SA2 encryption IV (optional)
    #[arg(long, requires("sa2"))]
    sa2_iv: Option<String>,

    /// Input SA2 key IV (optional)
    #[arg(long)]
    sa2_key_iv: Option<String>,

    /// Output BBBS SKSA
    #[arg(default_value_t = String::from("out.sksa"))]
    outfile: String,
}

#[derive(Debug)]
pub struct Args {
    pub virage2: IOType,
    pub bootrom: IOType,
    pub sk: IOType,
    pub sa1: IOType,
    pub sa1_cid: u32,
    pub sa1_key: BbAesKey,
    pub sa1_iv: BbAesIv,
    pub sa1_key_iv: BbAesIv,
    pub sa2: Option<IOType>,
    pub sa2_cid: Option<u32>,
    pub sa2_key: Option<BbAesKey>,
    pub sa2_iv: Option<BbAesIv>,
    pub sa2_key_iv: Option<BbAesIv>,
    pub outfile: IOType,
}

const BLANK_KEY: BbAesKey = [0; 16];
const BLANK_IV: BbAesIv = [0; 16];

impl TryFrom<Cli> for Args {
    type Error = hex::FromHexError;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        fn replace_extension_or(orig: &Path, replace: &[&str], with: &str) -> PathBuf {
            match orig.extension() {
                Some(_)
                    if replace.iter().map(OsString::from).any(|s| {
                        s.to_ascii_lowercase() == orig.extension().unwrap().to_ascii_lowercase()
                    }) =>
                {
                    orig.with_extension(with)
                }
                None => orig.with_extension(with),
                _ => {
                    let mut s = orig.as_os_str().to_owned();
                    s.push(format!(".{with}"));
                    s.into()
                }
            }
        }

        let virage2 = IOType::input(value.virage2);
        let bootrom = IOType::input(value.bootrom);
        let sk = IOType::input(value.sk);

        let sa1 = IOType::input(value.sa1);
        let sa1_cid = value.sa1_cid;
        let sa1_key = value
            .sa1_key
            .map(<_>::from_hex)
            .transpose()?
            .unwrap_or(BLANK_KEY);
        let sa1_iv = value
            .sa1_iv
            .map(<_>::from_hex)
            .transpose()?
            .unwrap_or(BLANK_IV);
        let sa1_key_iv = value
            .sa1_key_iv
            .map(<_>::from_hex)
            .transpose()?
            .unwrap_or(BLANK_IV);

        let sa2 = value.sa2.map(IOType::input);
        let sa2_cid = value.sa2_cid;
        let mut sa2_key = value.sa2_key.map(<_>::from_hex).transpose()?;
        let mut sa2_iv = value.sa2_iv.map(<_>::from_hex).transpose()?;
        let mut sa2_key_iv = value.sa2_key_iv.map(<_>::from_hex).transpose()?;

        if sa2.is_some() {
            if sa2_key.is_none() {
                sa2_key.replace(BLANK_KEY);
            }

            if sa2_iv.is_none() {
                sa2_iv.replace(BLANK_IV);
            }

            if sa2_key_iv.is_none() {
                sa2_key_iv.replace(BLANK_IV);
            }
        }

        let outfile = IOType::output(value.outfile);

        Ok(Self {
            virage2,
            bootrom,
            sk,
            sa1,
            sa1_cid,
            sa1_key,
            sa1_iv,
            sa1_key_iv,
            sa2,
            sa2_cid,
            sa2_key,
            sa2_iv,
            sa2_key_iv,
            outfile,
        })
    }
}

pub fn parse_args() -> Result<Args, hex::FromHexError> {
    Cli::parse().try_into()
}
