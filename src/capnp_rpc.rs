//! Cap'n Proto RPC for Cloudflare Tunnel registration
//!
//! Protocol (from cloudflared source control.go + registration_client.go):
//!
//!   cloudflared (RPC client)  ←→  edge (RPC server, RegistrationServer)
//!
//!   1. h2 control stream opened (ReadWriteCloser)
//!   2. capnp-rpc twoparty transport over that stream
//!   3. conn.Bootstrap() → get RegistrationServer capability from edge
//!   4. Call RegisterConnection(auth, tunnelId, connIndex, options)
//!   5. Edge replies with ConnectionDetails (location, uuid)
//!   6. Keep stream alive for graceful shutdown / config updates
//!
//! We use capnp-rpc's twoparty client with manually encoded structs
//! (no capnpc code generation needed).

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::debug;

/// Interface ID for RegistrationServer (from tunnelrpc.capnp)
pub const REGISTRATION_SERVER_ID: u64 = 0xf71695ec7fe85497;
pub const METHOD_REGISTER: u16 = 0;
pub const METHOD_UNREGISTER: u16 = 1;
pub const METHOD_UPDATE_CONFIG: u16 = 2;

// ── capnp wire encoding ────────────────────────────────────────────────────
//
// Struct sizes (from generated Go code, ObjectSize fields):
//   registerConnection params: DataSize=8, PointerCount=3
//   TunnelAuth:                DataSize=0, PointerCount=2
//   ConnectionOptions:         DataSize=8, PointerCount=2
//   ClientInfo:                DataSize=0, PointerCount=4

/// Build the capnp-framed struct for RegisterConnection params.
/// Returns a complete single-segment capnp message (no RPC framing).
pub fn encode_register_connection(
    account_tag: &str,
    tunnel_secret: &[u8],
    tunnel_id: &[u8; 16],
    conn_index: u8,
    client_id: &[u8; 16],
    version: &str,
    arch: &str,
    features: &[&str],
) -> Vec<u8> {
    let mut seg = SegBuilder::new();

    // Allocate structs (data_words, ptr_count)
    let params   = seg.alloc_struct(1, 3); // data[0]=connIndex, ptr[0]=auth, ptr[1]=tunnelId, ptr[2]=options
    let auth     = seg.alloc_struct(0, 2); // ptr[0]=accountTag, ptr[1]=tunnelSecret
    let options  = seg.alloc_struct(1, 2); // ptr[0]=client, ptr[1]=originLocalIp(null)
    let client   = seg.alloc_struct(0, 4); // ptr[0]=clientId, ptr[1]=features, ptr[2]=version, ptr[3]=arch

    // Allocate data blobs
    let account_tag_w   = seg.alloc_text(account_tag);
    let secret_w        = seg.alloc_data(tunnel_secret);
    let tunnel_id_w     = seg.alloc_data(tunnel_id);
    let client_id_w     = seg.alloc_data(client_id);
    let version_w       = seg.alloc_text(version);
    let arch_w          = seg.alloc_text(arch);

    let feat_ws: Vec<usize> = features.iter().map(|f| seg.alloc_text(f)).collect();
    let feat_list_w = seg.alloc_ptr_list(features.len());

    // ── Wire up params ────────────────────────────────────────────────────
    seg.set_u8(params.data_w, 0, conn_index);
    seg.set_struct_ptr(params.ptr_w, 0, auth.data_w,    0, 2);
    seg.set_data_ptr  (params.ptr_w, 1, tunnel_id_w,    tunnel_id.len());
    seg.set_struct_ptr(params.ptr_w, 2, options.data_w, 1, 2);

    // ── Wire up auth ──────────────────────────────────────────────────────
    seg.set_text_ptr(auth.ptr_w, 0, account_tag_w, account_tag.len() + 1);
    seg.set_data_ptr(auth.ptr_w, 1, secret_w,      tunnel_secret.len());

    // ── Wire up options ───────────────────────────────────────────────────
    seg.set_struct_ptr(options.ptr_w, 0, client.data_w, 0, 4);
    // ptr[1] = originLocalIp: leave null

    // ── Wire up client ────────────────────────────────────────────────────
    seg.set_data_ptr    (client.ptr_w, 0, client_id_w,   16);
    seg.set_ptr_list_ptr(client.ptr_w, 1, feat_list_w,   features.len());
    seg.set_text_ptr    (client.ptr_w, 2, version_w,     version.len() + 1);
    seg.set_text_ptr    (client.ptr_w, 3, arch_w,        arch.len() + 1);

    // ── Wire up features list entries ─────────────────────────────────────
    for (i, (&fw, f)) in feat_ws.iter().zip(features.iter()).enumerate() {
        seg.set_list_text_entry(feat_list_w, i, fw, f.len() + 1);
    }

    seg.finish(params.data_w, 1, 3)
}

/// Parse a ConnectionResponse capnp struct.
/// Returns Ok(location_name) on connectionDetails, Err(cause) on error.
pub fn decode_connection_response(data: &[u8]) -> Result<String> {
    // Skip capnp framing header (4 or 8 bytes depending on segment count)
    // Single segment: [0x00000000][seg0_size_words][root_ptr][...data...]
    if data.len() < 24 {
        bail!("ConnectionResponse too short: {} bytes", data.len());
    }

    // Frame: 4 bytes (seg_count-1=0) + 4 bytes (seg0_size) = 8 bytes
    let seg_data = &data[8..];
    if seg_data.len() < 8 {
        bail!("No room for root pointer");
    }

    // Root pointer (struct pointer at word 0)
    let root_ptr = u64::from_le_bytes(seg_data[0..8].try_into().unwrap());
    let ptr_type = root_ptr & 3;
    if ptr_type != 0 {
        bail!("Root is not a struct pointer: type={}", ptr_type);
    }
    let offset = ((root_ptr as i32) >> 2) as i64;
    let data_words = ((root_ptr >> 32) & 0xFFFF) as usize;
    let ptr_count  = ((root_ptr >> 48) & 0xFFFF) as usize;

    let struct_start = (1 + offset) as usize * 8; // in bytes from seg_data[0]
    if struct_start + (data_words + ptr_count) * 8 > seg_data.len() {
        bail!("ConnectionResponse struct out of bounds");
    }

    // ConnectionResponse union: result = union { error @0, connectionDetails @1 }
    // Union discriminant: data[0] bits 0-15
    let struct_data = &seg_data[struct_start..];
    let discriminant = u16::from_le_bytes(struct_data[0..2].try_into().unwrap());

    match discriminant {
        0 => {
            // error: ConnectionError { cause @0 :Text, retryAfter @1, shouldRetry @2 }
            // ptr[0] = cause text
            let ptrs_start = data_words * 8;
            let cause = read_text_ptr(struct_data, ptrs_start, 0, seg_data)
                .unwrap_or_else(|_| "unknown error".to_string());
            bail!("Edge rejected connection: {}", cause);
        }
        1 => {
            // connectionDetails: { uuid @0 :Data, locationName @1 :Text, ... }
            // ptr[0] = uuid, ptr[1] = locationName
            let ptrs_start = data_words * 8;
            let location = read_text_ptr(struct_data, ptrs_start, 1, seg_data)
                .unwrap_or_else(|_| "unknown".to_string());
            Ok(location)
        }
        _ => bail!("Unknown ConnectionResponse discriminant: {}", discriminant),
    }
}

fn read_text_ptr(struct_data: &[u8], ptrs_start: usize, slot: usize, seg: &[u8]) -> Result<String> {
    let ptr_offset = ptrs_start + slot * 8;
    if ptr_offset + 8 > struct_data.len() {
        bail!("ptr out of bounds");
    }
    let ptr = u64::from_le_bytes(struct_data[ptr_offset..ptr_offset+8].try_into().unwrap());
    if ptr == 0 { return Ok(String::new()); }
    let ptr_type = ptr & 3;
    if ptr_type != 1 { bail!("Not a list pointer"); }
    let offset = ((ptr as i32) >> 2) as i64;
    let elem_type = (ptr >> 32) & 7;
    let elem_count = (ptr >> 35) as usize;

    // elem_type 2 = byte
    if elem_type != 2 { bail!("Not a byte list"); }

    // ptr is at struct_data[ptr_offset], which is at some word in the segment
    // The target is at: ptr_word + 1 + offset words from the segment start
    // We need to know the absolute word offset of this ptr in the segment.
    // For simplicity: assume struct starts at seg[8] (word 1 of segment)
    // and ptrs_start is relative to struct start.
    let ptr_word_in_seg = (8 + (struct_data.as_ptr() as usize - seg.as_ptr() as usize)
        + ptr_offset) / 8;
    let target_word = (ptr_word_in_seg as i64 + 1 + offset) as usize;
    let target_byte = target_word * 8;

    if target_byte + elem_count > seg.len() {
        bail!("Text data out of bounds");
    }
    let bytes = &seg[target_byte..target_byte + elem_count.saturating_sub(1)]; // strip NUL
    Ok(String::from_utf8_lossy(bytes).to_string())
}

// ── capnp-rpc two-party framing ────────────────────────────────────────────
//
// capnp-rpc message format (rpc.capnp):
//   Message union:
//     unimplemented @0
//     abort @1
//     call @2 :Call
//     return @3 :Return
//     ...bootstrap @8 :Bootstrap
//
// Bootstrap: { questionId @0 :UInt32, deprecatedObjectId @1 :AnyPointer }
// Call: {
//   questionId @0, target @1 :MessageTarget,
//   interfaceId @2 :UInt64, methodId @3 :UInt16,
//   params @4 :Payload, ...
// }
// Return: { answerId @0, union { results @1 :Payload, exception @2 ... } }

/// Build a capnp-rpc Bootstrap message (questionId=0, objectId=null)
pub fn build_bootstrap_msg(question_id: u32) -> Vec<u8> {
    // Message struct: DataSize=1word, PointerCount=1
    //   data[0] bits 0-15 = union discriminant: bootstrap=8
    // Bootstrap struct: DataSize=1word, PointerCount=1
    //   data[0] = questionId (u32)
    //   ptr[0] = deprecatedObjectId (null = empty capability)
    let mut seg = SegBuilder::new();

    let msg       = seg.alloc_struct(1, 1); // Message: data=1w ptr=1
    let bootstrap = seg.alloc_struct(1, 1); // Bootstrap: data=1w ptr=1

    // Message discriminant = 8 (bootstrap)
    seg.set_u16(msg.data_w, 0, 8);
    // Message ptr[0] = bootstrap struct
    seg.set_struct_ptr(msg.ptr_w, 0, bootstrap.data_w, 1, 1);

    // Bootstrap questionId
    seg.set_u32(bootstrap.data_w, 0, question_id);
    // Bootstrap deprecatedObjectId: null (leave as 0)

    seg.finish(msg.data_w, 1, 1)
}

/// Build a capnp-rpc Call message for RegisterConnection
pub fn build_call_msg(
    question_id: u32,
    params_struct_bytes: &[u8],
) -> Vec<u8> {
    // We need to embed the params struct inline in the Call message's Payload.
    // The params_struct_bytes is a complete framed capnp message.
    // In capnp-rpc, params are embedded directly (same segment), not as nested messages.
    //
    // For now, we inline the raw params struct words by parsing the framed message
    // and extracting just the struct data.
    let params_words = strip_framing(params_struct_bytes);

    let mut seg = SegBuilder::new();

    // Message struct: DataSize=1word, PointerCount=1
    let msg     = seg.alloc_struct(1, 1);
    // Call struct: DataSize=3words, PointerCount=3 (from rpc.capnp generated code)
    let call    = seg.alloc_struct(3, 3);
    // Payload struct: DataSize=0, PointerCount=2 (content, capTable)
    let payload = seg.alloc_struct(0, 2);
    // Inline the params struct words
    let params_w = seg.alloc_raw(&params_words);

    // Message discriminant = 2 (call)
    seg.set_u16(msg.data_w, 0, 2);
    seg.set_struct_ptr(msg.ptr_w, 0, call.data_w, 3, 3);

    // Call fields:
    // data[0] u32 = questionId
    seg.set_u32(call.data_w, 0, question_id);
    // data[0] u16 at offset 4 = methodId = 0 (registerConnection)
    seg.set_u16(call.data_w + 0, 4, METHOD_REGISTER);
    // data[1] u64 = interfaceId
    seg.set_u64(call.data_w + 1, 0, REGISTRATION_SERVER_ID);
    // data[2] u32 bits 0-1 = sendResultsTo discriminant = 0 (caller)
    // ptr[0] = target: null (use bootstrap answer, questionId=0)
    // We need to encode a PromisedAnswer target pointing to question 0
    let target_w = seg.alloc_struct(1, 1); // MessageTarget struct
    seg.set_u16(target_w.data_w, 0, 1); // discriminant = 1 (promisedAnswer)
    let pa_w = seg.alloc_struct(1, 1); // PromisedAnswer
    seg.set_u32(pa_w.data_w, 0, 0); // questionId = 0 (bootstrap answer)
    // transformations = empty list (null ptr)
    seg.set_struct_ptr(target_w.ptr_w, 0, pa_w.data_w, 1, 1); // hmm complex

    // Simpler: target = imported capability (cap index 0 in cap table)
    // Actually let's use importedCap = 0
    // MessageTarget discriminant: 0=importedCap, 1=promisedAnswer
    // Use importedCap=0 (the bootstrapped cap)
    seg.set_u16(target_w.data_w, 0, 0); // discriminant = 0 (importedCap)
    seg.set_u32(target_w.data_w, 4, 0); // importedCap.id = 0

    seg.set_struct_ptr(call.ptr_w, 0, target_w.data_w, 1, 1);

    // ptr[1] = params (Payload)
    seg.set_struct_ptr(call.ptr_w, 1, payload.data_w, 0, 2);

    // Payload ptr[0] = content = our params struct
    // The params_w points to the first word of the inlined params struct.
    // We need a struct pointer to it with the right DataSize/PointerCount.
    // From registerConnection params: DataSize=8(1word), PointerCount=3
    seg.set_struct_ptr(payload.ptr_w, 0, params_w, 1, 3);

    seg.finish(msg.data_w, 1, 1)
}

/// Strip capnp frame header and root pointer, return raw segment words
fn strip_framing(framed: &[u8]) -> Vec<u64> {
    if framed.len() < 16 { return Vec::new(); }
    // header: [seg_count-1 u32][seg0_size u32] then optional padding
    let seg_count = u32::from_le_bytes(framed[0..4].try_into().unwrap()) + 1;
    let header_words = (seg_count as usize + 2) / 2; // rounded up to word
    let header_bytes = header_words * 8;
    // skip root pointer (1 word after header)
    let data_start = header_bytes + 8;
    if data_start >= framed.len() { return Vec::new(); }
    let data = &framed[data_start..];
    data.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

// ── Segment builder ────────────────────────────────────────────────────────

struct StructAlloc {
    data_w: usize, // word index of data section start
    ptr_w:  usize, // word index of pointer section start
}

struct SegBuilder {
    words: Vec<u64>,
}

impl SegBuilder {
    fn new() -> Self { Self { words: Vec::with_capacity(32) } }

    fn alloc(&mut self, n: usize) -> usize {
        let w = self.words.len();
        self.words.resize(w + n, 0);
        w
    }

    fn alloc_struct(&mut self, data_words: usize, ptr_count: usize) -> StructAlloc {
        let w = self.alloc(data_words + ptr_count);
        StructAlloc { data_w: w, ptr_w: w + data_words }
    }

    fn alloc_text(&mut self, s: &str) -> usize {
        let b = s.as_bytes();
        let words = (b.len() + 1 + 7) / 8;
        let w = self.alloc(words);
        self.write_bytes(w, b);
        w
    }

    fn alloc_data(&mut self, d: &[u8]) -> usize {
        let words = (d.len() + 7) / 8;
        let w = self.alloc(words);
        self.write_bytes(w, d);
        w
    }

    fn alloc_ptr_list(&mut self, count: usize) -> usize {
        self.alloc(count.max(1))
    }

    fn alloc_raw(&mut self, words: &[u64]) -> usize {
        let w = self.alloc(words.len());
        self.words[w..w+words.len()].copy_from_slice(words);
        w
    }

    fn write_bytes(&mut self, word: usize, data: &[u8]) {
        let dst = self.as_bytes_mut();
        let start = word * 8;
        dst[start..start + data.len()].copy_from_slice(data);
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.words.as_mut_ptr() as *mut u8,
                self.words.len() * 8,
            )
        }
    }

    fn set_u8(&mut self, word: usize, byte: usize, v: u8) {
        self.as_bytes_mut()[word * 8 + byte] = v;
    }
    fn set_u16(&mut self, word: usize, byte: usize, v: u16) {
        let b = self.as_bytes_mut();
        let i = word * 8 + byte;
        b[i..i+2].copy_from_slice(&v.to_le_bytes());
    }
    fn set_u32(&mut self, word: usize, byte: usize, v: u32) {
        let b = self.as_bytes_mut();
        let i = word * 8 + byte;
        b[i..i+4].copy_from_slice(&v.to_le_bytes());
    }
    fn set_u64(&mut self, word: usize, _byte: usize, v: u64) {
        self.words[word] = v.to_le_bytes().iter().fold(0u64, |a, &b| a | (b as u64));
        self.words[word] = u64::from_le_bytes(v.to_le_bytes());
    }

    /// Struct pointer at ptr_section[slot] → target struct at target_word
    fn set_struct_ptr(&mut self, ptr_base: usize, slot: usize,
                      target_word: usize, data_words: u16, ptr_count: u16) {
        let ptr_word = ptr_base + slot;
        let offset   = (target_word as i64) - (ptr_word as i64) - 1;
        let lo = ((offset << 2) & 0xFFFF_FFFF) as u32; // type=0 struct
        let hi = (data_words as u32) | ((ptr_count as u32) << 16);
        self.words[ptr_word] = (lo as u64) | ((hi as u64) << 32);
    }

    /// Data (byte list) pointer
    fn set_data_ptr(&mut self, ptr_base: usize, slot: usize, target_word: usize, len: usize) {
        let ptr_word = ptr_base + slot;
        let offset   = (target_word as i64) - (ptr_word as i64) - 1;
        let lo = (((offset << 2) | 1) & 0xFFFF_FFFF) as u32; // type=1 list
        let hi = ((len as u32) << 3) | 2; // elem_size=2 (byte)
        self.words[ptr_word] = (lo as u64) | ((hi as u64) << 32);
    }

    /// Text pointer (same as data, len includes NUL)
    fn set_text_ptr(&mut self, ptr_base: usize, slot: usize, target_word: usize, char_count: usize) {
        self.set_data_ptr(ptr_base, slot, target_word, char_count);
    }

    /// List-of-pointers pointer
    fn set_ptr_list_ptr(&mut self, ptr_base: usize, slot: usize, target_word: usize, count: usize) {
        let ptr_word = ptr_base + slot;
        let offset   = (target_word as i64) - (ptr_word as i64) - 1;
        let lo = (((offset << 2) | 1) & 0xFFFF_FFFF) as u32;
        let hi = ((count as u32) << 3) | 6; // elem_size=6 (pointer)
        self.words[ptr_word] = (lo as u64) | ((hi as u64) << 32);
    }

    /// Write a text pointer into list-of-pointers[index]
    fn set_list_text_entry(&mut self, list_base: usize, index: usize,
                           target_word: usize, char_count: usize) {
        self.set_text_ptr(list_base, index, target_word, char_count);
    }

    /// Serialize to framed capnp message with given root struct info
    fn finish(self, root_word: usize, data_words: u16, ptr_count: u16) -> Vec<u8> {
        // Frame: [0u32 (1 segment)][seg_size_words u32]
        let seg_size = (1 + self.words.len()) as u32; // 1 for root ptr
        let mut out = Vec::with_capacity((2 + 1 + self.words.len()) * 8);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&seg_size.to_le_bytes());
        // Root struct pointer (at word 0 of segment, points to root_word)
        let root_ptr_word: usize = 0; // the frame header is outside the segment
        let offset = root_word as i64; // ptr at seg[0], target at seg[1+root_word]... actually:
        // The root ptr is the first word of the segment (after frame header).
        // Its offset field means: target is at (ptr_position + 1 + offset) words.
        // ptr_position = 0 (first word of segment), so target = 1 + offset.
        // We want target = root_word (0-based in our word array),
        // so: root_word = 1 + offset → offset = root_word - 1
        let real_offset = root_word as i64 - 1;
        let lo = ((real_offset << 2) & 0xFFFF_FFFF) as u32;
        let hi = (data_words as u32) | ((ptr_count as u32) << 16);
        let root_ptr: u64 = (lo as u64) | ((hi as u64) << 32);
        out.extend_from_slice(&root_ptr.to_le_bytes());
        for w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}
