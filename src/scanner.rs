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

/// Hex prefix of a Sapling-capable tx, nVersion=3 (i16 LE) of any nType:
/// other txs are skipped without decoding them. Special transactions
/// (masternode registrations and the like, nType != 0) can carry shield
/// spends and outputs too; their extra payload comes after the Sapling
/// data, which is all the scanner and the wallets read. Leaving one out
/// would cost every wallet a note commitment, and their tree would no
/// longer match the chain.
const SAPLING_VERSION_HEX: &str = "0300";

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
        if !raw_hex.starts_with(SAPLING_VERSION_HEX) {
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

/// What the shield index needs of a raw block (`getblock <hash> 0`).
#[derive(Debug)]
pub struct RawBlockScan {
    /// Display-order hex, as RPC answers show them.
    pub hash: String,
    pub prev_hash: String,
    /// `None` when the block has no shield transactions.
    pub shield: Option<ShieldBlock>,
}

/// Reads a raw block at `height`: its hash, its parent and its shield
/// transactions. A raw block costs the node far less than the JSON of
/// `getblock <hash> 2`, and shield data needs only the raw transactions.
///
/// The transactions found must hash to the header's merkle root, so a
/// block this reader gets wrong is an error, never wrong shield data.
pub fn scan_raw_block(height: u32, block: &[u8]) -> Result<RawBlockScan, String> {
    let mut r = Reader { data: block, pos: 0 };
    // PIVX Core's CBlockHeader.
    let version = r.u32()?;
    if version < 4 {
        // Hashed with Quark (pre-2018 blocks).
        return Err(format!("block version {version}"));
    }
    let prev = r.take(32)?.to_vec();
    let merkle_root = r.take(32)?.to_vec();
    let time = r.u32()?;
    r.take(8)?; // nBits, nNonce
    if version < 7 {
        r.take(32)?; // nAccumulatorCheckpoint
    }
    if version >= 8 {
        r.take(32)?; // hashFinalSaplingRoot
    }
    let hash = sha256d(&block[..r.pos]);

    let count = r.compact_size()?;
    let mut txids = Vec::with_capacity(count.min(block.len() / 60));
    let mut txs = Vec::new();
    for _ in 0..count {
        let start = r.pos;
        skip_tx(&mut r)?;
        let raw = &block[start..r.pos];
        txids.push(sha256d(raw));
        if raw.starts_with(&[0x03, 0x00]) {
            match parse_sapling_tx(raw) {
                Ok(Some(compact)) => txs.push(ShieldTx { raw: raw.to_vec(), compact: Some(compact) }),
                Ok(None) => {}
                Err(e) => return Err(format!("tx {}: {e}", display_hex(txids.last().unwrap()))),
            }
        }
    }
    if txids.is_empty() || merkle(txids)[..] != merkle_root[..] {
        return Err("the transactions don't match the merkle root".into());
    }
    // What's left is a proof-of-stake block's signature.
    if r.pos < block.len() {
        let len = r.compact_size()?;
        r.take(len)?;
        if r.pos != block.len() {
            return Err(format!("{} bytes after the block", block.len() - r.pos));
        }
    }

    Ok(RawBlockScan {
        hash: display_hex(&hash),
        prev_hash: display_hex(&prev),
        shield: (!txs.is_empty()).then_some(ShieldBlock { height, time, txs }),
    })
}

/// Moves `r` past one transaction, as PIVX Core's SerializeTransaction
/// writes it.
fn skip_tx(r: &mut Reader) -> Result<(), String> {
    let version = r.u16()?;
    let n_type = r.u16()?;
    for _ in 0..r.compact_size()? {
        r.take(36)?; // prevout
        let script = r.compact_size()?;
        r.take(script)?;
        r.take(4)?; // nSequence
    }
    for _ in 0..r.compact_size()? {
        r.take(8)?; // nValue
        let script = r.compact_size()?;
        r.take(script)?;
    }
    r.take(4)?; // nLockTime
    if version >= 3 {
        // Optional<SaplingTxData>
        if r.flag()? {
            r.take(8)?; // valueBalance
            let spends = r.compact_size()?;
            r.take(spends.checked_mul(SPEND_DESC_SIZE).ok_or("too many spends")?)?;
            let outputs = r.compact_size()?;
            r.take(outputs.checked_mul(OUTPUT_DESC_SIZE).ok_or("too many outputs")?)?;
            r.take(64)?; // bindingSig
        }
        // Optional<std::vector<uint8_t>> extraPayload of special txs
        if n_type != 0 && r.flag()? {
            let len = r.compact_size()?;
            r.take(len)?;
        }
    }
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len()).ok_or("truncated block")?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn flag(&mut self) -> Result<bool, String> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(format!("bad Optional flag {b}")),
        }
    }

    fn compact_size(&mut self) -> Result<usize, String> {
        let (n, len) = read_compact_size(self.data, self.pos)?;
        self.pos += len;
        Ok(n)
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(Sha256::digest(data)).into()
}

/// Bitcoin's merkle root: pairs hashed level by level, an odd last hash
/// paired with itself.
fn merkle(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let mut both = [0u8; 64];
                both[..32].copy_from_slice(&pair[0]);
                both[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
                sha256d(&both)
            })
            .collect();
    }
    level[0]
}

/// Hash bytes in RPC display order (reversed) as hex.
fn display_hex(hash: &[u8]) -> String {
    hash.iter().rev().map(|b| format!("{b:02x}")).collect()
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
        assert_eq!(hex::hex_decode(SAPLING_VERSION_HEX).unwrap(), SAPLING_HEADER[..2]);
    }

    /// A v3 tx of type `n_type` with one shield output, then `payload`.
    fn shield_tx(n_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut tx = vec![0x03, 0x00];
        tx.extend(n_type.to_le_bytes());
        tx.push(0); // vin
        tx.push(0); // vout
        tx.extend([0u8; 4]); // nLockTime
        tx.push(0x01); // sapData present
        tx.extend(0i64.to_le_bytes()); // valueBalance
        tx.push(0); // spends
        tx.push(1); // outputs
        let mut out = vec![0u8; OUTPUT_DESC_SIZE];
        out[32] = 0x22; // cmu
        tx.extend(out);
        tx.extend([0u8; 64]); // bindingSig
        tx.extend_from_slice(payload);
        tx
    }

    #[test]
    fn special_transactions_with_shield_data_are_kept() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        // ProRegTx (nType 1) with an extra payload, a normal shield tx,
        // a special tx without shield data and a v1 tx.
        let proreg = shield_tx(1, &[0x01, 0x03, 0xAA, 0xBB, 0xCC]);
        let normal = shield_tx(0, &[]);
        let mut no_shield = vec![0x03, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x00];
        no_shield.extend([0x01, 0x01, 0xAA]);
        let block = serde_json::json!({
            "height": 900, "time": 1,
            "tx": [
                { "txid": "a", "hex": hex(&proreg) },
                { "txid": "b", "hex": hex(&normal) },
                { "txid": "c", "hex": hex(&no_shield) },
                { "txid": "d", "hex": "01000000" },
            ],
        });
        let b = scan_block_json(&block).unwrap().unwrap();
        assert_eq!(b.txs.len(), 2);
        assert_eq!(b.txs[0].raw, proreg, "kept whole, payload included");
        assert_eq!(b.txs[0].compact.as_ref().unwrap().outputs[0].cmu[0], 0x22);
        assert_eq!(b.txs[1].raw, normal);
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
        // txid: 815921e01f022c640276427a37e8cf0bddd23eb77878fa03835ef97764d53394
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

    /// A regtest block (version 11) with a coinbase, a coinstake, a shield
    /// transaction and a transparent one, as `getblock <hash> 0` gave it.
    const REGTEST_BLOCK: &str = include_str!("../tests/regtest_shield_block.hex");

    #[test]
    fn raw_block_from_the_node() {
        let block = hex::hex_decode(REGTEST_BLOCK.trim()).unwrap();
        let scan = scan_raw_block(16402, &block).unwrap();
        assert_eq!(scan.hash, "bf0dd46974cfea4b9feaf2647b49b8a343797bcce9f345d285fcf0a74248bbd8");
        assert_eq!(scan.prev_hash, "efeedac6192d1adfef663eb8a17b93cdea06e8d178a6f6bf049b97e62fb05997");
        let shield = scan.shield.unwrap();
        assert_eq!((shield.height, shield.time), (16402, 1792146473));
        assert_eq!(shield.txs.len(), 1);
        assert!(shield.txs[0].raw.starts_with(&[0x03, 0x00]));
        assert!(!shield.txs[0].compact.as_ref().unwrap().outputs.is_empty());

        // A changed byte in a transaction no longer matches the merkle root.
        let mut changed = block.clone();
        let at = changed.len() - 200;
        changed[at] ^= 1;
        assert!(scan_raw_block(16402, &changed).is_err());
        // Nor do extra bytes, or a cut block.
        let mut longer = block.clone();
        longer.push(0);
        assert!(scan_raw_block(16402, &longer).is_err());
        assert!(scan_raw_block(16402, &block[..block.len() - 1]).is_err());
    }

    /// A version 8+ block of `txs`, with a block signature.
    fn raw_block(version: u32, txs: &[Vec<u8>]) -> Vec<u8> {
        let mut b = version.to_le_bytes().to_vec();
        b.extend([0x11; 32]); // hashPrevBlock
        b.extend(merkle(txs.iter().map(|t| sha256d(t)).collect()));
        b.extend(7u32.to_le_bytes()); // nTime
        b.extend([0u8; 8]);
        b.extend([0u8; 32]); // hashFinalSaplingRoot
        b.push(txs.len() as u8);
        for t in txs {
            b.extend(t);
        }
        b.push(3);
        b.extend([0xAA, 0xBB, 0xCC]); // vchBlockSig
        b
    }

    #[test]
    fn raw_block_with_mainnet_and_special_transactions() {
        let mainnet = hex::hex_decode(include_str!("../tests/mainnet_sapling_tx.hex").trim()).unwrap();
        // v1 coinbase-like: 1 input with a script, 1 output.
        let mut v1 = vec![0x01, 0, 0, 0, 1];
        v1.extend([0u8; 36]);
        v1.extend([2, 0x51, 0x52]);
        v1.extend([0xff; 4]);
        v1.push(1);
        v1.extend(5u64.to_le_bytes());
        v1.extend([1, 0x51]);
        v1.extend([0u8; 4]);
        let proreg = shield_tx(1, &[0x01, 0x03, 0xAA, 0xBB, 0xCC]);
        // A special tx without shield data but with a payload.
        let mut no_shield = vec![0x03, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0x00];
        no_shield.extend([0x01, 0x02, 0xAA, 0xBB]);
        let block = raw_block(11, &[v1, mainnet.clone(), no_shield, proreg.clone()]);
        let scan = scan_raw_block(5, &block).unwrap();
        assert_eq!(scan.prev_hash, "11".repeat(32));
        let shield = scan.shield.unwrap();
        assert_eq!(shield.txs.len(), 2);
        assert_eq!(shield.txs[0].raw, mainnet);
        assert_eq!(shield.txs[0].compact.as_ref().unwrap().nullifiers.len(), 2);
        assert_eq!(shield.txs[1].raw, proreg);
        assert_eq!(scan.hash, display_hex(&sha256d(&block[..80 + 32])));

        // Without the signature too (a proof-of-work block).
        let unsigned = &block[..block.len() - 4];
        assert_eq!(scan_raw_block(5, unsigned).unwrap().shield.unwrap().txs.len(), 2);
        // Old Quark-hashed blocks are left to the JSON path.
        assert!(scan_raw_block(5, &raw_block(3, &[mainnet])).is_err());
    }
}
