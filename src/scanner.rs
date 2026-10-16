/// Block scanner — extracts Sapling transactions from the PIVX node.
///
/// Reads `getblock <hash> 2` answers (raw tx hex inline) and keeps the
/// Sapling transactions.
use crate::hex;

/// PIVX Sapling transaction header: nVersion=3 (i16 LE) + nType=0 (i16 LE).
/// Kerrigan/Dash uses nType=10 (0x0a 0x00) for its Sapling-capable transactions.
#[cfg(test)]
const SAPLING_HEADER: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

/// Size of each spend description in bytes.
const SPEND_DESC_SIZE: usize = 384;

/// Size of each output description in bytes.
const OUTPUT_DESC_SIZE: usize = 948;

/// Size of enc_ciphertext in bytes.
const ENC_CIPHERTEXT_SIZE: usize = 580;

/// Size of out_ciphertext in bytes.
const OUT_CIPHERTEXT_SIZE: usize = 80;

// ---------------------------------------------------------------------------
// Scanned block types
// ---------------------------------------------------------------------------

/// A scanned shield block.
#[derive(Debug, Clone)]
pub struct ShieldBlock {
    /// Block height.
    pub height: u32,
    /// Block timestamp.
    pub time: u32,
    /// Sapling transactions in this block.
    pub txs: Vec<ShieldTx>,
}

/// A Sapling transaction with extracted compact data.
#[derive(Debug, Clone)]
pub struct ShieldTx {
    /// Full raw transaction bytes (for 0x03 legacy compat).
    pub raw: Vec<u8>,
    /// Extracted compact data (for 0x04/0x05 formats).
    pub compact: Option<CompactTx>,
}

/// Compact transaction data — proofs and signatures stripped.
#[derive(Debug, Clone)]
pub struct CompactTx {
    /// Nullifiers from Sapling spends (32 bytes each).
    pub nullifiers: Vec<[u8; 32]>,
    /// Compact outputs.
    pub outputs: Vec<CompactOutput>,
}

/// A compact Sapling output.
#[derive(Debug, Clone)]
pub struct CompactOutput {
    /// Value commitment (32 bytes) — needed for OVK outgoing recovery.
    pub cv: [u8; 32],
    /// Note commitment (32 bytes).
    pub cmu: [u8; 32],
    /// Ephemeral public key (32 bytes).
    pub epk: [u8; 32],
    /// Encrypted ciphertext (580 bytes).
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    /// Outgoing ciphertext (80 bytes) — for sender recovery.
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

/// Hex prefix of a Sapling-capable tx (see `SAPLING_HEADER`): other txs
/// are skipped without decoding them.
const SAPLING_HEADER_HEX: &str = "03000000";

/// Shield transactions of a `getblock <hash> 2` answer, or `None` when the
/// block has none.
pub fn scan_block_json(block_json: &serde_json::Value) -> Result<Option<ShieldBlock>, ScanError> {
    let height = block_json
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or(ScanError::Parse("missing 'height' in block".into()))? as u32;
    let txs_json = block_json
        .get("tx")
        .and_then(|t| t.as_array())
        .ok_or(ScanError::Parse("missing 'tx' array in block".into()))?;
    let time = block_json.get("time").and_then(|t| t.as_u64()).unwrap_or(0) as u32;

    let mut txs = Vec::new();
    for tx in txs_json {
        let raw_hex = tx
            .get("hex")
            .and_then(|h| h.as_str())
            .ok_or_else(|| ScanError::Parse(format!("block {height}: tx without hex (needs verbosity 2)")))?;
        if !raw_hex.starts_with(SAPLING_HEADER_HEX) {
            continue;
        }
        let tx_bytes = hex::hex_decode(raw_hex)
            .ok_or_else(|| ScanError::Parse(format!("block {height}: bad tx hex")))?;
        match parse_sapling_tx(&tx_bytes) {
            Ok(Some(compact)) => txs.push(ShieldTx { raw: tx_bytes, compact: Some(compact) }),
            Ok(None) => {}
            Err(e) => {
                let txid = tx.get("txid").and_then(|t| t.as_str()).unwrap_or("?");
                log::warn!("Block {height} tx {txid}: not parsed as Sapling ({e}), skipped");
            }
        }
    }

    Ok((!txs.is_empty()).then_some(ShieldBlock { height, time, txs }))
}

// ---------------------------------------------------------------------------
// PIVX Sapling transaction parser
// ---------------------------------------------------------------------------

/// Parse a raw PIVX v3 transaction and extract Sapling data.
///
/// PIVX serialization (from PIVX Core `SerializeTransaction`):
///   nVersion(i16) + nType(i16) + vin + vout + nLockTime(u32)
///   + sapData discriminant(u8: 0x01=present, 0x00=absent)
///   + SaplingTxData { valueBalance(i64) + vShieldedSpend + vShieldedOutput + bindingSig(64) }
///
/// The discriminant is the Optional<SaplingTxData> presence flag from PIVX's serialize.h.
/// Kerrigan/Dash uses nType=10 with an extra payload wrapper instead.
pub fn parse_sapling_tx(data: &[u8]) -> Result<Option<CompactTx>, String> {
    let mut pos = 4; // skip version header

    // Skip vin
    let (vin_count, br) = read_compact_size(data, pos)?;
    pos += br;
    for _ in 0..vin_count {
        pos += 32 + 4; // prevout (txid + vout)
        let (script_len, br) = read_compact_size(data, pos)?;
        pos += br + script_len; // scriptSig
        pos += 4; // sequence
        if pos > data.len() { return Err("truncated vin".into()); }
    }

    // Skip vout
    let (vout_count, br) = read_compact_size(data, pos)?;
    pos += br;
    for _ in 0..vout_count {
        pos += 8; // value
        let (script_len, br) = read_compact_size(data, pos)?;
        pos += br + script_len; // scriptPubKey
        if pos > data.len() { return Err("truncated vout".into()); }
    }

    // Skip nLockTime
    pos += 4;

    // If nothing remains after nLockTime, no Sapling data
    if pos >= data.len() {
        return Ok(None);
    }

    // PIVX Sapling fields (Optional<SaplingTxData>):
    // discriminant (1 byte: 0x01=present) + valueBalance (8 bytes) + spends + outputs + [bindingSig]
    let discriminant = data[pos];
    pos += 1;
    if discriminant == 0x00 {
        return Ok(None); // sapData absent
    }
    if pos + 8 > data.len() { return Ok(None); }
    pos += 8; // valueBalance

    // Parse spend and output descriptions
    parse_sapling_descs(data, pos)
}

/// Parse Sapling spend/output descriptions from the given offset.
fn parse_sapling_descs(data: &[u8], start: usize) -> Result<Option<CompactTx>, String> {
    let mut pos = start;

    // Spend descriptions
    let (num_spends, br) = read_compact_size(data, pos)?;
    pos += br;

    let mut nullifiers = Vec::new();
    for _ in 0..num_spends {
        if pos + SPEND_DESC_SIZE > data.len() { return Err("truncated spend".into()); }
        // cv(32) + anchor(32) + nullifier(32) + rk(32) + proof(192) + sig(64)
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&data[pos + 64..pos + 96]);
        nullifiers.push(nf);
        pos += SPEND_DESC_SIZE;
    }

    // Output descriptions
    let (num_outputs, br) = read_compact_size(data, pos)?;
    pos += br;

    let mut outputs = Vec::new();
    for _ in 0..num_outputs {
        if pos + OUTPUT_DESC_SIZE > data.len() { return Err("truncated output".into()); }
        // cv(32) + cmu(32) + epk(32) + enc(580) + out(80) + proof(192)
        let mut cv = [0u8; 32];
        cv.copy_from_slice(&data[pos..pos + 32]);

        let mut cmu = [0u8; 32];
        cmu.copy_from_slice(&data[pos + 32..pos + 64]);

        let mut epk = [0u8; 32];
        epk.copy_from_slice(&data[pos + 64..pos + 96]);

        let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ciphertext.copy_from_slice(&data[pos + 96..pos + 96 + ENC_CIPHERTEXT_SIZE]);

        let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
        out_ciphertext.copy_from_slice(&data[pos + 96 + ENC_CIPHERTEXT_SIZE..pos + 96 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE]);

        outputs.push(CompactOutput { cv, cmu, epk, enc_ciphertext, out_ciphertext });
        pos += OUTPUT_DESC_SIZE;
    }

    if nullifiers.is_empty() && outputs.is_empty() {
        return Ok(None);
    }

    Ok(Some(CompactTx { nullifiers, outputs }))
}

/// Read a Bitcoin compact size (varint).
pub(crate) fn read_compact_size(data: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if pos >= data.len() { return Err("read past end".into()); }
    match data[pos] {
        n if n < 253 => Ok((n as usize, 1)),
        253 => {
            if pos + 3 > data.len() { return Err("truncated varint".into()); }
            Ok((u16::from_le_bytes([data[pos+1], data[pos+2]]) as usize, 3))
        }
        254 => {
            if pos + 5 > data.len() { return Err("truncated varint".into()); }
            Ok((u32::from_le_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]) as usize, 5))
        }
        255 => {
            if pos + 9 > data.len() { return Err("truncated varint".into()); }
            Ok((u64::from_le_bytes([
                data[pos+1], data[pos+2], data[pos+3], data[pos+4],
                data[pos+5], data[pos+6], data[pos+7], data[pos+8],
            ]) as usize, 9))
        }
        _ => unreachable!(),
    }
}


// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ScanError {
    Parse(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "scanner parse error: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_compact_size_single_byte() {
        let data = [42u8];
        let (val, consumed) = read_compact_size(&data, 0).unwrap();
        assert_eq!(val, 42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn read_compact_size_two_byte() {
        let data = [253u8, 0x00, 0x01]; // 256
        let (val, consumed) = read_compact_size(&data, 0).unwrap();
        assert_eq!(val, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn read_compact_size_four_byte() {
        let data = [254u8, 0x01, 0x00, 0x01, 0x00]; // 65537
        let (val, consumed) = read_compact_size(&data, 0).unwrap();
        assert_eq!(val, 65537);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn read_compact_size_past_end() {
        let data = [];
        assert!(read_compact_size(&data, 0).is_err());
    }

    #[test]
    fn sapling_header_correct() {
        // PIVX: nVersion=3 (i16 LE) + nType=0 (i16 LE)
        assert_eq!(SAPLING_HEADER, [0x03, 0x00, 0x00, 0x00]);
        assert_eq!(hex::hex_decode(SAPLING_HEADER_HEX).unwrap(), SAPLING_HEADER);
    }

    #[test]
    fn spend_output_sizes_match_pivx_core() {
        // From PIVX Core: SpendDescriptionV4 and OutputDescriptionV4
        // cv(32) + anchor(32) + nullifier(32) + rk(32) + zkproof(192) + spendAuthSig(64)
        assert_eq!(SPEND_DESC_SIZE, 32 + 32 + 32 + 32 + 192 + 64);
        // cv(32) + cmu(32) + epk(32) + encCiphertext(580) + outCiphertext(80) + zkproof(192)
        assert_eq!(OUTPUT_DESC_SIZE, 32 + 32 + 32 + 580 + 80 + 192);
    }

    #[test]
    fn parse_no_sapling_data() {
        // v3 tx with no Optional<SaplingTxData> — ends after nLockTime
        let mut tx = Vec::new();
        tx.extend_from_slice(&SAPLING_HEADER);
        tx.push(0); // vin = 0
        tx.push(0); // vout = 0
        tx.extend([0u8; 4]); // nLockTime

        let result = parse_sapling_tx(&tx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_discriminant_absent() {
        // Optional<SaplingTxData> discriminant = 0x00 (absent)
        let mut tx = Vec::new();
        tx.extend_from_slice(&SAPLING_HEADER);
        tx.push(0); // vin = 0
        tx.push(0); // vout = 0
        tx.extend([0u8; 4]); // nLockTime
        tx.push(0x00); // discriminant = absent

        let result = parse_sapling_tx(&tx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_discriminant_present_empty() {
        // Optional<SaplingTxData> present but 0 spends, 0 outputs
        let mut tx = Vec::new();
        tx.extend_from_slice(&SAPLING_HEADER);
        tx.push(0); // vin = 0
        tx.push(0); // vout = 0
        tx.extend([0u8; 4]); // nLockTime
        tx.push(0x01); // discriminant = present
        tx.extend([0u8; 8]); // valueBalance = 0
        tx.push(0); // nSpends = 0
        tx.push(0); // nOutputs = 0

        let result = parse_sapling_tx(&tx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_real_mainnet_tx() {
        // Real PIVX mainnet tx from block 5361234
        // txid: 1c49a5a4c2db52cd6a0695ed0df3d0807c4b70044294fab3e6b0d7b6e01eeb72
        // 2 spends, 1 output, valueBalance = 13000000 sat
        let hex = include_str!("../tests/mainnet_sapling_tx.hex");
        let tx_bytes = hex::hex_decode(hex.trim()).expect("valid hex");

        // Verify header
        assert_eq!(&tx_bytes[..4], &SAPLING_HEADER);
        assert_eq!(tx_bytes.len(), 1835);

        // Parse
        let result = parse_sapling_tx(&tx_bytes).unwrap();
        assert!(result.is_some(), "should find Sapling data");

        let compact = result.unwrap();
        assert_eq!(compact.nullifiers.len(), 2, "2 spends → 2 nullifiers");
        assert_eq!(compact.outputs.len(), 1, "1 shielded output");

        // Verify nullifiers are non-zero
        assert!(compact.nullifiers[0].iter().any(|&b| b != 0));
        assert!(compact.nullifiers[1].iter().any(|&b| b != 0));

        // Verify output fields are non-zero
        let out = &compact.outputs[0];
        assert!(out.cv.iter().any(|&b| b != 0));
        assert!(out.cmu.iter().any(|&b| b != 0));
        assert!(out.epk.iter().any(|&b| b != 0));
        assert!(out.enc_ciphertext.iter().any(|&b| b != 0));
        assert!(out.out_ciphertext.iter().any(|&b| b != 0));
    }

    #[test]
    fn parse_with_transparent_vout() {
        // Synthetic tx: vin=0, vout=1 (P2PKH), then Sapling with 0 spends + 1 output
        let mut tx = Vec::new();
        tx.extend_from_slice(&SAPLING_HEADER);
        tx.push(0); // vin = 0
        tx.push(1); // vout = 1
        // vout[0]: value=1 PIV (100000000 sat)
        tx.extend(100_000_000u64.to_le_bytes());
        // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        tx.push(25); // script length
        tx.push(0x76); tx.push(0xa9); tx.push(0x14);
        tx.extend([0xAA; 20]); // dummy pubkey hash
        tx.push(0x88); tx.push(0xac);
        // nLockTime
        tx.extend([0u8; 4]);
        // discriminant = present
        tx.push(0x01);
        // valueBalance
        tx.extend(50_000_000i64.to_le_bytes());
        // 0 spends
        tx.push(0);
        // 1 output (948 bytes of dummy data)
        tx.push(1);
        let mut output_desc = vec![0u8; OUTPUT_DESC_SIZE];
        // cv
        output_desc[0] = 0x11;
        // cmu
        output_desc[32] = 0x22;
        // epk
        output_desc[64] = 0x33;
        // enc_ciphertext starts at 96
        output_desc[96] = 0x44;
        // out_ciphertext starts at 676
        output_desc[676] = 0x55;
        tx.extend_from_slice(&output_desc);

        let result = parse_sapling_tx(&tx).unwrap();
        assert!(result.is_some());

        let compact = result.unwrap();
        assert_eq!(compact.nullifiers.len(), 0);
        assert_eq!(compact.outputs.len(), 1);
        assert_eq!(compact.outputs[0].cv[0], 0x11);
        assert_eq!(compact.outputs[0].cmu[0], 0x22);
        assert_eq!(compact.outputs[0].epk[0], 0x33);
        assert_eq!(compact.outputs[0].enc_ciphertext[0], 0x44);
        assert_eq!(compact.outputs[0].out_ciphertext[0], 0x55);
    }
}
