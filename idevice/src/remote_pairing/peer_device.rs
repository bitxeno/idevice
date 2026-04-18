use crate::IdeviceError;

use super::{opack, tlv};

#[derive(Debug, Clone, Default)]
pub struct PeerDevice {
    pub account_id: Option<String>,
    pub alt_irk: Option<Vec<u8>>,
    pub model: Option<String>,
    pub name: Option<String>,
    pub remotepairing_udid: Option<String>,
}

impl PeerDevice {
    pub fn from_info_dictionary(dict: &plist::Dictionary) -> Self {
        Self {
            account_id: dict
                .get("accountID")
                .and_then(|v| v.as_string())
                .map(str::to_string),
            alt_irk: dict
                .get("altIRK")
                .and_then(|v| v.as_data())
                .map(|v| v.to_vec()),
            model: dict
                .get("model")
                .and_then(|v| v.as_string())
                .map(str::to_string),
            name: dict
                .get("name")
                .and_then(|v| v.as_string())
                .map(str::to_string),
            remotepairing_udid: dict
                .get("remotepairing_udid")
                .and_then(|v| v.as_string())
                .map(str::to_string),
        }
    }
}

pub fn parse_info_dictionary_from_tlv(
    entries: &[tlv::TLV8Entry],
) -> Result<plist::Dictionary, IdeviceError> {
    if tlv::contains_component(entries, tlv::PairingDataComponentType::ErrorResponse) {
        return Err(IdeviceError::UnexpectedResponse(
            "TLV error response in pair record save".into(),
        ));
    }

    let info = tlv::collect_component_data(entries, tlv::PairingDataComponentType::Info);
    if info.is_empty() {
        return Err(IdeviceError::UnexpectedResponse(
            "missing info payload in pair record response".into(),
        ));
    }

    let info_plist = opack::opack_to_plist(&info).map_err(|e| {
        IdeviceError::UnexpectedResponse(
            format!("failed to parse OPACK info payload from pair record response: {e}").into(),
        )
    })?;

    let info_dict = info_plist
        .as_dictionary()
        .ok_or(IdeviceError::UnexpectedResponse(
            "info OPACK payload is not a dictionary".into(),
        ))?;

    Ok(info_dict.to_owned())
}

pub fn parse_peer_device_from_tlv(entries: &[tlv::TLV8Entry]) -> Result<PeerDevice, IdeviceError> {
    let info = parse_info_dictionary_from_tlv(entries)?;
    Ok(PeerDevice::from_info_dictionary(&info))
}
