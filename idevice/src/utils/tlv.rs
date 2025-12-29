//! TLV (Type-Length-Value) encoding/decoding for Apple pairing protocol
//!
//! This module provides utilities for working with TLV-encoded data
//! as used in the wireless pairing protocol.

/// A buffer for building TLV-encoded data
#[derive(Debug, Clone)]
pub struct TlvBuf {
    data: Vec<u8>,
}

impl TlvBuf {
    /// Creates a new empty TLV buffer
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Appends data with a type tag to the buffer
    ///
    /// For data longer than 255 bytes, this will split into multiple TLV entries
    /// with the same type tag (fragmentation).
    pub fn append(&mut self, tag: u8, data: &[u8]) {
        // TLV can only store 255 bytes per entry, so fragment larger data
        for chunk in data.chunks(255) {
            self.data.push(tag);
            self.data.push(chunk.len() as u8);
            self.data.extend_from_slice(chunk);
        }
    }

    /// Gets the underlying data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the buffer and returns the data
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Gets the length of the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for TlvBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a u8 value from TLV data by tag
pub fn tlv_get_uint8(data: &[u8], tag: u8) -> Option<u8> {
    let mut offset = 0;
    while offset + 2 <= data.len() {
        let t = data[offset];
        let l = data[offset + 1] as usize;
        if offset + 2 + l > data.len() {
            break;
        }
        if t == tag && l >= 1 {
            return Some(data[offset + 2]);
        }
        offset += 2 + l;
    }
    None
}

/// Extract a variable-length uint from TLV data by tag
pub fn tlv_get_uint(data: &[u8], tag: u8) -> Option<u64> {
    let bytes = tlv_get_data(data, tag)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut result = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as u64) << (i * 8); // little-endian
    }
    Some(result)
}

/// Extract raw data from TLV by tag
///
/// This handles fragmented data (multiple entries with same tag) by concatenating them.
pub fn tlv_get_data(data: &[u8], tag: u8) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut found = false;
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let t = data[offset];
        let l = data[offset + 1] as usize;
        if offset + 2 + l > data.len() {
            break;
        }
        if t == tag {
            found = true;
            result.extend_from_slice(&data[offset + 2..offset + 2 + l]);
        }
        offset += 2 + l;
    }

    if found { Some(result) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = TlvBuf::new();
        buf.append(0x01, b"hello");
        buf.append(0x02, &[0x42]);
        buf.append(0x03, &[0x01, 0x02, 0x03, 0x04]);

        let data = buf.data();
        assert_eq!(tlv_get_data(data, 0x01), Some(b"hello".to_vec()));
        assert_eq!(tlv_get_uint8(data, 0x02), Some(0x42));
        assert_eq!(tlv_get_uint(data, 0x03), Some(0x04030201));
    }

    #[test]
    fn test_tlv_fragmentation() {
        let mut buf = TlvBuf::new();
        let large_data = vec![0xAB; 300]; // > 255 bytes
        buf.append(0x05, &large_data);

        let data = buf.data();
        let extracted = tlv_get_data(data, 0x05).unwrap();
        assert_eq!(extracted, large_data);
    }
}
