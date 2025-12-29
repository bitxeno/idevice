//! OPACK encoding/decoding for Apple device info
//!
//! OPACK is a binary format similar to MessagePack used by Apple for
//! encoding device info in the wireless pairing protocol.
//! This implementation follows libimobiledevice-glue.

use plist::Value;

/// OPACK type tags
const OPACK_TRUE: u8 = 0x01;
const OPACK_FALSE: u8 = 0x02;
const OPACK_TERM: u8 = 0x03;
const OPACK_DATE: u8 = 0x06;

const OPACK_INT8: u8 = 0x30;
const OPACK_INT32: u8 = 0x32;
const OPACK_INT64: u8 = 0x33;

const OPACK_FLOAT: u8 = 0x35;
const OPACK_DOUBLE: u8 = 0x36;

const OPACK_STRING_SHORT_BASE: u8 = 0x40;
const OPACK_STRING_LEN8: u8 = 0x61;
const OPACK_STRING_LEN16: u8 = 0x62;
const OPACK_STRING_LEN32: u8 = 0x63;
const OPACK_STRING_LEN64: u8 = 0x64;

const OPACK_DATA_SHORT_BASE: u8 = 0x70;
const OPACK_DATA_LEN8: u8 = 0x91;
const OPACK_DATA_LEN16: u8 = 0x92;
const OPACK_DATA_LEN32: u8 = 0x93;
const OPACK_DATA_LEN64: u8 = 0x94;

const OPACK_ARRAY_SHORT_BASE: u8 = 0xD0;
const OPACK_ARRAY_LONG: u8 = 0xDF;

const OPACK_DICT_SHORT_BASE: u8 = 0xE0;
const OPACK_DICT_LONG: u8 = 0xEF;

const MAC_EPOCH: f64 = 978307200.0;

/// Encode a plist value to OPACK format
pub fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_value(value, &mut buf);
    buf
}

fn encode_value(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Dictionary(dict) => {
            let count = dict.len();
            if count < 15 {
                buf.push(OPACK_DICT_SHORT_BASE + count as u8);
            } else {
                buf.push(OPACK_DICT_LONG);
            }
            for (key, val) in dict.iter() {
                encode_string(key, buf);
                encode_value(val, buf);
            }
            if count >= 15 {
                buf.push(OPACK_TERM);
            }
        }
        Value::Array(arr) => {
            let count = arr.len();
            if count < 15 {
                buf.push(OPACK_ARRAY_SHORT_BASE + count as u8);
            } else {
                buf.push(OPACK_ARRAY_LONG);
            }
            for val in arr.iter() {
                encode_value(val, buf);
            }
            if count >= 15 {
                buf.push(OPACK_TERM);
            }
        }
        Value::String(s) => encode_string(s, buf),
        Value::Data(d) => encode_data(d.as_ref(), buf),
        Value::Boolean(b) => {
            buf.push(if *b { OPACK_TRUE } else { OPACK_FALSE });
        }
        Value::Integer(i) => {
            if let Some(n) = i.as_unsigned() {
                encode_uint(n, buf);
            } else if let Some(n) = i.as_signed() {
                encode_int(n, buf);
            }
        }
        Value::Real(r) => {
            let dval = *r;
            if dval as f32 as f64 == dval {
                let fval = dval as f32;
                buf.push(OPACK_FLOAT);
                buf.extend_from_slice(&fval.to_be_bytes());
            } else {
                buf.push(OPACK_DOUBLE);
                buf.extend_from_slice(&dval.to_be_bytes());
            }
        }
        Value::Date(date) => {
            let system_time: std::time::SystemTime = (*date).into();
            let seconds = system_time
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs_f64();
            let mac_seconds = seconds - MAC_EPOCH;
            buf.push(OPACK_DATE);
            buf.extend_from_slice(&mac_seconds.to_be_bytes());
        }
        _ => {} // Fallback
    }
}

fn encode_string(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 0x20 {
        buf.push(OPACK_STRING_SHORT_BASE + len as u8);
    } else if len <= 0xFF {
        buf.push(OPACK_STRING_LEN8);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(OPACK_STRING_LEN16);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xFFFFFFFF {
        buf.push(OPACK_STRING_LEN32);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        buf.push(OPACK_STRING_LEN64);
        buf.extend_from_slice(&(len as u64).to_le_bytes());
    }
    buf.extend_from_slice(bytes);
}

fn encode_data(d: &[u8], buf: &mut Vec<u8>) {
    let len = d.len();
    if len <= 0x20 {
        buf.push(OPACK_DATA_SHORT_BASE + len as u8);
    } else if len <= 0xFF {
        buf.push(OPACK_DATA_LEN8);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(OPACK_DATA_LEN16);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xFFFFFFFF {
        buf.push(OPACK_DATA_LEN32);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        buf.push(OPACK_DATA_LEN64);
        buf.extend_from_slice(&(len as u64).to_le_bytes());
    }
    buf.extend_from_slice(d);
}

fn encode_uint(n: u64, buf: &mut Vec<u8>) {
    if n <= 0x27 {
        buf.push(8 + n as u8);
    } else if n <= 0xFF {
        buf.push(OPACK_INT8);
        buf.push(n as u8);
    } else if n <= 0xFFFFFFFF {
        buf.push(OPACK_INT32);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(OPACK_INT64);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn encode_int(n: i64, buf: &mut Vec<u8>) {
    if n >= 0 && n <= 0x27 {
        buf.push(8 + n as u8);
    } else if n >= i8::MIN as i64 && n <= i8::MAX as i64 {
        buf.push(OPACK_INT8);
        buf.push(n as i8 as u8);
    } else if n >= i32::MIN as i64 && n <= i32::MAX as i64 {
        buf.push(OPACK_INT32);
        buf.extend_from_slice(&(n as i32).to_le_bytes());
    } else {
        buf.push(OPACK_INT64);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Decode OPACK data to a plist value
pub fn decode(data: &[u8]) -> Option<Value> {
    let mut offset = 0;
    decode_value(data, &mut offset, 0)
}

fn decode_value(data: &[u8], offset: &mut usize, level: u32) -> Option<Value> {
    if *offset >= data.len() {
        return None;
    }
    let tag = data[*offset];
    *offset += 1;

    match tag {
        OPACK_TRUE => Some(Value::Boolean(true)),
        OPACK_FALSE => Some(Value::Boolean(false)),
        OPACK_TERM => None, // Should be handled by caller
        OPACK_DATE => {
            if *offset + 8 > data.len() {
                return None;
            }
            let mac_seconds = f64::from_be_bytes(data[*offset..*offset + 8].try_into().ok()?);
            *offset += 8;
            let seconds = mac_seconds + MAC_EPOCH;
            let system_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(seconds);
            Some(Value::Date(system_time.into()))
        }
        0x08..=0x2F => Some(Value::Integer(((tag - 8) as i64).into())),
        OPACK_INT8 => {
            if *offset >= data.len() {
                return None;
            }
            let v = data[*offset] as i8;
            *offset += 1;
            Some(Value::Integer((v as i64).into()))
        }
        OPACK_INT32 => {
            if *offset + 4 > data.len() {
                return None;
            }
            let v = i32::from_le_bytes(data[*offset..*offset + 4].try_into().ok()?);
            *offset += 4;
            Some(Value::Integer((v as i64).into()))
        }
        OPACK_INT64 => {
            if *offset + 8 > data.len() {
                return None;
            }
            let v = i64::from_le_bytes(data[*offset..*offset + 8].try_into().ok()?);
            *offset += 8;
            Some(Value::Integer(v.into()))
        }
        OPACK_FLOAT => {
            if *offset + 4 > data.len() {
                return None;
            }
            let v = f32::from_be_bytes(data[*offset..*offset + 4].try_into().ok()?);
            *offset += 4;
            Some(Value::Real(v as f64))
        }
        OPACK_DOUBLE => {
            if *offset + 8 > data.len() {
                return None;
            }
            let v = f64::from_be_bytes(data[*offset..*offset + 8].try_into().ok()?);
            *offset += 8;
            Some(Value::Real(v))
        }
        0x40..=0x60 => {
            let len = (tag - 0x40) as usize;
            decode_string_with_len(data, offset, len)
        }
        OPACK_STRING_LEN8 => {
            if *offset >= data.len() {
                return None;
            }
            let len = data[*offset] as usize;
            *offset += 1;
            decode_string_with_len(data, offset, len)
        }
        OPACK_STRING_LEN16 => {
            if *offset + 2 > data.len() {
                return None;
            }
            let len = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            decode_string_with_len(data, offset, len)
        }
        OPACK_STRING_LEN32 => {
            if *offset + 4 > data.len() {
                return None;
            }
            let len = u32::from_le_bytes(data[*offset..*offset + 4].try_into().ok()?) as usize;
            *offset += 4;
            decode_string_with_len(data, offset, len)
        }
        OPACK_STRING_LEN64 => {
            if *offset + 8 > data.len() {
                return None;
            }
            let len = u64::from_le_bytes(data[*offset..*offset + 8].try_into().ok()?) as usize;
            *offset += 8;
            decode_string_with_len(data, offset, len)
        }
        0x70..=0x90 => {
            let len = (tag - 0x70) as usize;
            decode_data_with_len(data, offset, len)
        }
        OPACK_DATA_LEN8 => {
            if *offset >= data.len() {
                return None;
            }
            let len = data[*offset] as usize;
            *offset += 1;
            decode_data_with_len(data, offset, len)
        }
        OPACK_DATA_LEN16 => {
            if *offset + 2 > data.len() {
                return None;
            }
            let len = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            decode_data_with_len(data, offset, len)
        }
        OPACK_DATA_LEN32 => {
            if *offset + 4 > data.len() {
                return None;
            }
            let len = u32::from_le_bytes(data[*offset..*offset + 4].try_into().ok()?) as usize;
            *offset += 4;
            decode_data_with_len(data, offset, len)
        }
        OPACK_DATA_LEN64 => {
            if *offset + 8 > data.len() {
                return None;
            }
            let len = u64::from_le_bytes(data[*offset..*offset + 8].try_into().ok()?) as usize;
            *offset += 8;
            decode_data_with_len(data, offset, len)
        }
        0xD0..=0xDF => {
            let mut arr = Vec::new();
            let num_children = if tag < OPACK_ARRAY_LONG {
                (tag - OPACK_ARRAY_SHORT_BASE) as u32
            } else {
                u32::MAX
            };
            let mut i = 0;
            while i < num_children {
                if *offset < data.len() && data[*offset] == OPACK_TERM {
                    *offset += 1;
                    break;
                }
                if let Some(val) = decode_value(data, offset, level + 1) {
                    arr.push(val);
                } else {
                    break;
                }
                i += 1;
            }
            Some(Value::Array(arr))
        }
        0xE0..=0xEF => {
            let mut dict = plist::Dictionary::new();
            let num_children = if tag < OPACK_DICT_LONG {
                (tag - OPACK_DICT_SHORT_BASE) as u32
            } else {
                u32::MAX
            };
            let mut i = 0;
            while i < num_children {
                if *offset < data.len() && data[*offset] == OPACK_TERM {
                    *offset += 1;
                    break;
                }
                if let Some(key_val) = decode_value(data, offset, level + 1) {
                    if let Some(key) = key_val.as_string() {
                        if let Some(val) = decode_value(data, offset, level + 1) {
                            dict.insert(key.to_string(), val);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
                i += 1;
            }
            Some(Value::Dictionary(dict))
        }
        _ => None,
    }
}

fn decode_string_with_len(data: &[u8], offset: &mut usize, len: usize) -> Option<Value> {
    if *offset + len > data.len() {
        return None;
    }
    let s = String::from_utf8(data[*offset..*offset + len].to_vec()).ok()?;
    *offset += len;
    Some(Value::String(s))
}

fn decode_data_with_len(data: &[u8], offset: &mut usize, len: usize) -> Option<Value> {
    if *offset + len > data.len() {
        return None;
    }
    let d = data[*offset..*offset + len].to_vec();
    *offset += len;
    Some(Value::Data(d.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opack_roundtrip() {
        let mut dict = plist::Dictionary::new();
        dict.insert("name".into(), Value::String("TestDevice".into()));
        dict.insert("model".into(), Value::String("MacBookPro".into()));
        dict.insert("enabled".into(), Value::Boolean(true));
        dict.insert("count".into(), Value::Integer(42.into()));

        let original = Value::Dictionary(dict);
        let encoded = encode(&original);
        let decoded = decode(&encoded).unwrap();

        if let (Value::Dictionary(orig), Value::Dictionary(dec)) = (&original, &decoded) {
            assert_eq!(orig.get("name"), dec.get("name"));
            assert_eq!(orig.get("model"), dec.get("model"));
            assert_eq!(orig.get("enabled"), dec.get("enabled"));
            assert_eq!(orig.get("count"), dec.get("count"));
        } else {
            panic!("Expected dictionaries");
        }
    }
}
