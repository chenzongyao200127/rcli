use super::{verify_file, verify_path};
use crate::{get_reader, CmdExcutor};
use crate::{process_text_key_decrypt, process_text_key_encrypt};
use anyhow::Ok;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use core::fmt;
use enum_dispatch::enum_dispatch;
use std::{path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExcutor)]
pub enum TextSubCommand {
    #[command(about = "Sign a message with a private key/shared key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a signed message")]
    Verify(TextVerifyOpts),

    #[command(about = "Generate a new key")]
    Generate(TextKeyGenerateOpts),

    #[command(about = "Encrypt a message")]
    Encrypt(TextEncryptOpts),

    #[command(about = "Decrypt a message")]
    Decrypt(TextDecryptOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "blake3", value_parser = parse_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(short, long)]
    pub sig: String,

    #[arg(long, default_value = "blake3", value_parser = parse_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextKeyGenerateOpts {
    #[arg(short, long, default_value = "blake3", value_parser = parse_format)]
    pub format: TextSignFormat,

    #[arg(short, long, value_parser = verify_path)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "xchacha20poly1305", value_parser = parse_encrypt_format)]
    pub format: TextEncryptFormat,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "xchacha20poly1305", value_parser = parse_encrypt_format)]
    pub format: TextEncryptFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

#[derive(Debug, Clone, Copy)]
pub enum TextEncryptFormat {
    XChaCha20Poly1305,
}

fn parse_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

fn parse_encrypt_format(format: &str) -> Result<TextEncryptFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::anyhow!("Invalid format")),
        }
    }
}

impl From<TextSignFormat> for &'static str {
    fn from(format: TextSignFormat) -> Self {
        match format {
            TextSignFormat::Blake3 => "blake3",
            TextSignFormat::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(*self))
    }
}

impl FromStr for TextEncryptFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "xchacha20poly1305" => Ok(TextEncryptFormat::XChaCha20Poly1305),
            _ => Err(anyhow::anyhow!("Invalid format")),
        }
    }
}

impl From<TextEncryptFormat> for &'static str {
    fn from(format: TextEncryptFormat) -> Self {
        match format {
            TextEncryptFormat::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }
}

impl fmt::Display for TextEncryptFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(*self))
    }
}

impl CmdExcutor for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = crate::get_content(&self.key)?;
        let sig = crate::process_text_sign(&mut reader, &key, self.format)?;
        let encoded = URL_SAFE_NO_PAD.encode(sig);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExcutor for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = crate::get_content(&self.key)?;
        let sig = URL_SAFE_NO_PAD.decode(&self.sig)?;
        let valid = crate::process_text_verify(&mut reader, &key, &sig, self.format)?;
        if valid {
            println!("Signature is valid");
        } else {
            println!("Signature is invalid");
        }
        Ok(())
    }
}

impl CmdExcutor for TextKeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let keys = crate::process_text_key_generate(self.format)?;
        for (name, key) in keys {
            let name = self.output.join(name);
            tokio::fs::write(name, key).await?;
        }
        Ok(())
    }
}

impl CmdExcutor for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = crate::get_content(&self.key)?;
        let encrypted = process_text_key_encrypt(&mut reader, &key, self.format)?;
        let encoded = URL_SAFE_NO_PAD.encode(encrypted);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExcutor for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = crate::get_content(&self.key)?;
        let input = crate::get_content(&self.input)?;
        let decoded = URL_SAFE_NO_PAD.decode(input)?;
        let plaintext = process_text_key_decrypt(&mut decoded.as_slice(), &key, self.format)?;
        println!(
            "Plaintext: {:?}",
            plaintext
                .to_ascii_lowercase()
                .iter()
                .map(|x| *x as char)
                .collect::<String>()
        );
        Ok(())
    }
}
