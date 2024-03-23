use anyhow::Result;
use bb::{bootrom_keys, BbAesIv, BbAesKey, BbShaHash, CmdHead, HashHex, Virage2, BLOCK_SIZE};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use soft_aes::aes::aes_enc_cbc;
use thiserror::Error;

use std::fmt::Display;
use std::io::Write;

pub mod args;

use args::Args;

const SK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum SKSAComponent {
    Sk,
    Sa1,
    Sa2,
}

impl Display for SKSAComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Sk => "SK",
                Self::Sa1 => "SA1",
                Self::Sa2 => "SA2",
            }
        )
    }
}

#[derive(Debug, Error)]
pub enum MakeSKSAError {
    #[error("Provided {0} is too long (got 0x{1:X} bytes, max 0x{2:X})")]
    ComponentTooLong(SKSAComponent, usize, usize),
}

// horrible hack so emoose's iQueTool code doesn't die on these SKSA blobs
// eventually I'll write a replacement and this won't be necessary
const DUMMY_CERTS_CRLS: &[u8] = include_bytes!("certcrl.bin");

pub fn build(args: Args) -> Result<()> {
    let virage2 = args.virage2.read()?;
    let virage2 = Virage2::read_from_buf(&virage2)?;

    let bootrom = args.bootrom.read()?;

    let (sk_key, sk_iv) = bootrom_keys(&bootrom)?;

    let mut sk = args.sk.read()?;

    if sk.len() > SK_SIZE {
        return Err(MakeSKSAError::ComponentTooLong(SKSAComponent::Sk, sk.len(), SK_SIZE).into());
    }

    if sk.len() < SK_SIZE {
        sk.resize(SK_SIZE, 0);
    }

    let mut sa1 = args.sa1.read()?;

    if sa1.len() > u32::MAX as _ {
        return Err(
            MakeSKSAError::ComponentTooLong(SKSAComponent::Sa1, sa1.len(), u32::MAX as _).into(),
        );
    }

    sa1.resize(sa1.len().next_multiple_of(BLOCK_SIZE), 0);

    let sa2 = args
        .sa2
        .map(|f| -> Result<Vec<u8>> {
            let sa2 = f.read()?;

            let mut encoder = DeflateEncoder::new(vec![], Compression::fast());
            encoder.write_all(&sa2)?;
            let mut sa2 = encoder.finish()?;

            if sa2.len() > u32::MAX as _ {
                return Err(MakeSKSAError::ComponentTooLong(
                    SKSAComponent::Sa2,
                    sa2.len(),
                    u32::MAX as _,
                )
                .into());
            }

            sa2.resize(sa2.len().next_multiple_of(BLOCK_SIZE), 0);

            Ok(sa2)
        })
        .transpose()?;

    let sk = aes_enc_cbc(&sk, &sk_key, &sk_iv, None).expect("encryption failed");

    let sa1_cmd = CmdHead::new_unsigned(
        args.sa1_key,
        args.sa1_iv,
        virage2.boot_app_key,
        args.sa1_key_iv,
        sa1.len() as _,
        args.sa1_cid,
    );

    let mut sa1_cmd = sa1_cmd.to_buf()?;
    sa1_cmd.extend(DUMMY_CERTS_CRLS);
    sa1_cmd.resize(BLOCK_SIZE, 0);

    let sa1 = aes_enc_cbc(&sa1, &args.sa1_key, &args.sa1_iv, None).expect("encryption failed");

    let sa2_cmd = sa2
        .as_ref()
        .map(|sa| -> Result<Vec<u8>> {
            let cmd = CmdHead::new_unsigned(
                args.sa2_key.unwrap(),
                args.sa2_iv.unwrap(),
                virage2.boot_app_key,
                args.sa2_key_iv.unwrap(),
                sa.len() as _,
                args.sa2_cid.unwrap(),
            );

            let mut cmd = cmd.to_buf()?;
            cmd.extend(DUMMY_CERTS_CRLS);
            cmd.resize(BLOCK_SIZE, 0);

            Ok(cmd)
        })
        .transpose()?;

    let sa2 = sa2.map(|sa| {
        aes_enc_cbc(&sa, &args.sa2_key.unwrap(), &args.sa2_iv.unwrap(), None)
            .expect("encryption failed")
    });

    let mut outfile = vec![];

    outfile.extend(sk);
    outfile.extend(sa1_cmd);
    outfile.extend(sa1);
    if let Some(sa2) = sa2 {
        outfile.extend(sa2_cmd.unwrap());
        outfile.extend(sa2);
    }

    args.outfile.write(outfile)?;

    Ok(())
}
