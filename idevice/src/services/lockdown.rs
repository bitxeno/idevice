//! iOS Lockdown Service Client
//!
//! Provides functionality for interacting with the lockdown service on iOS devices,
//! which is the primary service for device management and service discovery.

use plist::Value;
use tracing::error;

use crate::{Idevice, IdeviceError, IdeviceService, obf, pairing_file};

/// Client for interacting with the iOS lockdown service
///
/// This is the primary service for device management and provides:
/// - Access to device information and settings
/// - Service discovery and port allocation
/// - Session management and security
#[derive(Debug)]
pub struct LockdownClient {
    /// The underlying device connection with established lockdown service
    pub idevice: crate::Idevice,
}

impl IdeviceService for LockdownClient {
    /// Returns the lockdown service name as registered with the device
    fn service_name() -> std::borrow::Cow<'static, str> {
        obf!("com.apple.mobile.lockdown")
    }

    /// Establishes a connection to the lockdown service
    ///
    /// # Arguments
    /// * `provider` - Device connection provider
    ///
    /// # Returns
    /// A connected `LockdownClient` instance
    ///
    /// # Errors
    /// Returns `IdeviceError` if connection fails
    async fn connect(
        provider: &dyn crate::provider::IdeviceProvider,
    ) -> Result<Self, IdeviceError> {
        let idevice = provider.connect(Self::LOCKDOWND_PORT).await?;
        Ok(Self::new(idevice))
    }

    async fn from_stream(idevice: Idevice) -> Result<Self, crate::IdeviceError> {
        Ok(Self::new(idevice))
    }
}

impl LockdownClient {
    /// The default TCP port for the lockdown service
    pub const LOCKDOWND_PORT: u16 = 62078;

    /// Creates a new lockdown client from an existing device connection
    ///
    /// # Arguments
    /// * `idevice` - Pre-established device connection
    pub fn new(idevice: Idevice) -> Self {
        Self { idevice }
    }

    /// Retrieves a specific value from the device
    ///
    /// # Arguments
    /// * `value` - The name of the value to retrieve (e.g., "DeviceName")
    ///
    /// # Returns
    /// The requested value as a plist Value
    ///
    /// # Errors
    /// Returns `IdeviceError` if:
    /// - Communication fails
    /// - The requested value doesn't exist
    /// - The response is malformed
    ///
    /// # Example
    /// ```rust
    /// let device_name = client.get_value("DeviceName").await?;
    /// println!("Device name: {:?}", device_name);
    /// ```
    pub async fn get_value(
        &mut self,
        key: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Value, IdeviceError> {
        let request = crate::plist!({
            "Label": self.idevice.label.clone(),
            "Request": "GetValue",
            "Key":? key,
            "Domain":? domain
        });
        self.idevice.send_plist(request).await?;
        let message: plist::Dictionary = self.idevice.read_plist().await?;
        match message.get("Value") {
            Some(m) => Ok(m.to_owned()),
            None => Err(IdeviceError::UnexpectedResponse),
        }
    }

    /// Sets a value on the device
    ///
    /// # Arguments
    /// * `key` - The key to set
    /// * `value` - The plist value to set
    /// * `domain` - An optional domain to set by
    ///
    /// # Errors
    /// Returns `IdeviceError` if:
    /// - Communication fails
    /// - The response is malformed
    ///
    /// # Example
    /// ```rust
    /// client.set_value("EnableWifiDebugging", true.into(), Some("com.apple.mobile.wireless_lockdown".to_string())).await?;
    /// ```
    pub async fn set_value(
        &mut self,
        key: impl Into<String>,
        value: Value,
        domain: Option<&str>,
    ) -> Result<(), IdeviceError> {
        let key = key.into();

        let req = crate::plist!({
            "Label": self.idevice.label.clone(),
            "Request": "SetValue",
            "Key": key,
            "Value": value,
            "Domain":? domain
        });

        self.idevice.send_plist(req).await?;
        self.idevice.read_plist().await?;

        Ok(())
    }

    /// Starts a secure TLS session with the device
    ///
    /// # Arguments
    /// * `pairing_file` - Contains the device's identity and certificates
    ///
    /// # Returns
    /// `Ok(())` on successful session establishment
    ///
    /// # Errors
    /// Returns `IdeviceError` if:
    /// - No connection is established
    /// - The session request is denied
    /// - TLS handshake fails
    pub async fn start_session(
        &mut self,
        pairing_file: &pairing_file::PairingFile,
    ) -> Result<(), IdeviceError> {
        if self.idevice.socket.is_none() {
            return Err(IdeviceError::NoEstablishedConnection);
        }

        let legacy = self
            .get_value(Some("ProductVersion"), None)
            .await
            .ok()
            .as_ref()
            .and_then(|x| x.as_string())
            .and_then(|x| x.split(".").next())
            .and_then(|x| x.parse::<u8>().ok())
            .map(|x| x < 5)
            .unwrap_or(false);

        let request = crate::plist!({
            "Label": self.idevice.label.clone(),
            "Request": "StartSession",
            "HostID": pairing_file.host_id.clone(),
            "SystemBUID": pairing_file.system_buid.clone()

        });
        self.idevice.send_plist(request).await?;

        let response = self.idevice.read_plist().await?;
        match response.get("EnableSessionSSL") {
            Some(plist::Value::Boolean(enable)) => {
                if !enable {
                    return Err(IdeviceError::UnexpectedResponse);
                }
            }
            _ => {
                return Err(IdeviceError::UnexpectedResponse);
            }
        }

        self.idevice.start_session(pairing_file, legacy).await?;
        Ok(())
    }

    /// Requests to start a service on the device
    ///
    /// # Arguments
    /// * `identifier` - The service identifier (e.g., "com.apple.debugserver")
    ///
    /// # Returns
    /// A tuple containing:
    /// - The port number where the service is available
    /// - A boolean indicating whether SSL should be used
    ///
    /// # Errors
    /// Returns `IdeviceError` if:
    /// - The service cannot be started
    /// - The response is malformed
    /// - The requested service doesn't exist
    pub async fn start_service(
        &mut self,
        identifier: impl Into<String>,
    ) -> Result<(u16, bool), IdeviceError> {
        let identifier = identifier.into();
        let req = crate::plist!({
            "Request": "StartService",
            "Service": identifier,
        });
        self.idevice.send_plist(req).await?;
        let response = self.idevice.read_plist().await?;

        let ssl = match response.get("EnableServiceSSL") {
            Some(plist::Value::Boolean(ssl)) => ssl.to_owned(),
            _ => false, // over USB, this option won't exist
        };

        match response.get("Port") {
            Some(plist::Value::Integer(port)) => {
                if let Some(port) = port.as_unsigned() {
                    Ok((port as u16, ssl))
                } else {
                    error!("Port isn't an unsigned integer!");
                    Err(IdeviceError::UnexpectedResponse)
                }
            }
            _ => {
                error!("Response didn't contain an integer port");
                Err(IdeviceError::UnexpectedResponse)
            }
        }
    }

    /// Generates a pairing file and sends it to the device for trusting.
    /// Note that this does NOT save the file to usbmuxd's cache. That's a responsibility of the
    /// caller.
    /// Note that this function is computationally heavy in a debug build.
    ///
    /// # Arguments
    /// * `host_id` - The host ID, in the form of a UUID. Typically generated from the host name
    /// * `system_buid` - UUID fetched from usbmuxd. Doesn't appear to affect function.
    ///
    /// # Returns
    /// The newly generated pairing record
    ///
    /// # Errors
    /// Returns `IdeviceError`
    #[cfg(all(feature = "pair", feature = "rustls"))]
    pub async fn pair(
        &mut self,
        host_id: impl Into<String>,
        system_buid: impl Into<String>,
    ) -> Result<crate::pairing_file::PairingFile, IdeviceError> {
        let host_id = host_id.into();
        let system_buid = system_buid.into();

        let pub_key = self.get_value(Some("DevicePublicKey"), None).await?;
        let pub_key = match pub_key.as_data().map(|x| x.to_vec()) {
            Some(p) => p,
            None => {
                tracing::warn!("Did not get public key data response");
                return Err(IdeviceError::UnexpectedResponse);
            }
        };

        let wifi_mac = self.get_value(Some("WiFiAddress"), None).await?;
        let wifi_mac = match wifi_mac.as_string() {
            Some(w) => w,
            None => {
                tracing::warn!("Did not get WiFiAddress string");
                return Err(IdeviceError::UnexpectedResponse);
            }
        };

        let ca = crate::ca::generate_certificates(&pub_key, None).unwrap();
        let mut pair_record = crate::plist!(dict {
            "DevicePublicKey": pub_key,
            "DeviceCertificate": ca.dev_cert,
            "HostCertificate": ca.host_cert.clone(),
            "HostID": host_id,
            "RootCertificate": ca.host_cert,
            "RootPrivateKey": ca.private_key.clone(),
            "WiFiMACAddress": wifi_mac,
            "SystemBUID": system_buid,
        });

        let req = crate::plist!({
            "Label": self.idevice.label.clone(),
            "Request": "Pair",
            "PairRecord": pair_record.clone(),
            "ProtocolVersion": "2",
            "PairingOptions": {
                "ExtendedPairingErrors": true
            }
        });

        loop {
            self.idevice.send_plist(req.clone()).await?;
            match self.idevice.read_plist().await {
                Ok(escrow) => {
                    pair_record.insert("HostPrivateKey".into(), plist::Value::Data(ca.private_key));
                    if let Some(escrow) = escrow.get("EscrowBag").and_then(|x| x.as_data()) {
                        pair_record.insert("EscrowBag".into(), plist::Value::Data(escrow.to_vec()));
                    }

                    let p = crate::pairing_file::PairingFile::from_value(
                        &plist::Value::Dictionary(pair_record),
                    )?;

                    break Ok(p);
                }
                Err(IdeviceError::PairingDialogResponsePending) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => break Err(e),
            }
        }
    }

    /// Performs wireless (CU) pairing with the device using SRP6a protocol.
    /// This is used for Apple TV and other devices that require PIN-based pairing.
    ///
    /// # Arguments
    /// * `pairing_uuid` - A unique identifier for this pairing session (usually system BUID)
    /// * `pin_callback` - Async callback that returns the PIN displayed on the device
    /// * `acl` - Optional access control list for the pairing
    ///
    /// # Returns
    /// `Ok(())` on success, storing the SRP key internally for subsequent `pair_cu` call.
    ///
    /// # Errors
    /// Returns `IdeviceError` if pairing fails
    #[cfg(all(feature = "pair", feature = "rustls"))]
    pub async fn cu_pairing_create<F, Fut>(
        &mut self,
        pairing_uuid: impl Into<String>,
        pin_callback: F,
        acl: Option<plist::Dictionary>,
    ) -> Result<(Vec<u8>, Option<plist::Dictionary>), IdeviceError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        use ed25519_dalek::{Signer, SigningKey};
        use hkdf::Hkdf;
        use rand::RngCore;
        use sha2::Sha512;
        use srp::client::SrpClient;
        use srp::groups::G_3072;

        let pairing_uuid = pairing_uuid.into();

        // SRP6a constants
        const PAIR_SETUP: &[u8] = b"Pair-Setup";
        const PAIR_SETUP_ENCRYPT_SALT: &[u8] = b"Pair-Setup-Encrypt-Salt";
        const PAIR_SETUP_ENCRYPT_INFO: &[u8] = b"Pair-Setup-Encrypt-Info";
        const PAIR_SETUP_CONTROLLER_SIGN_SALT: &[u8] = b"Pair-Setup-Controller-Sign-Salt";
        const PAIR_SETUP_CONTROLLER_SIGN_INFO: &[u8] = b"Pair-Setup-Controller-Sign-Info";

        let mut current_state: u8 = 0;
        let final_state: u8 = 6;

        let mut salt: Option<Vec<u8>> = None;
        let mut server_pubkey: Option<Vec<u8>> = None;
        let mut srp_key: Option<Vec<u8>> = None;
        let mut srp_verifier = None;
        let mut setup_encryption_key = [0u8; 32];
        let mut device_info_value: Option<plist::Dictionary> = None;

        // Create SRP client
        let srp_client = SrpClient::<Sha512>::new(&G_3072);
        let mut rng = rand::rng();

        // Generate random ephemeral "a" value (64 bytes)
        let mut a = [0u8; 64];
        rng.fill_bytes(&mut a);
        tracing::debug!("SRP Ephemeral Private (a) hex: {:02X?}", a);

        let mut pin_callback = Some(pin_callback);

        while current_state != final_state {
            current_state += 1;

            let mut tlv = crate::utils::tlv::TlvBuf::new();

            if current_state == 1 {
                // State 1: Send method
                tlv.append(0x00, &[0x00]); // Method = 0
            } else if current_state == 3 {
                // State 3: Generate public key, compute SRP key, send response

                let s = salt.as_ref().ok_or(IdeviceError::UnexpectedResponse)?;
                let b_pub = server_pubkey
                    .as_ref()
                    .ok_or(IdeviceError::UnexpectedResponse)?;

                tracing::debug!("SRP Salt length: {}", s.len());
                tracing::debug!("SRP Salt hex: {:02X?}", s);
                tracing::debug!("SRP Server PubKey length: {}", b_pub.len());
                tracing::debug!(
                    "SRP Server PubKey hex (first 32): {:02X?}",
                    &b_pub[..32.min(b_pub.len())]
                );

                // Get PIN from callback
                let pin = pin_callback
                    .take()
                    .ok_or(IdeviceError::UnexpectedResponse)?()
                .await;
                let pin = pin.trim();
                tracing::debug!("Using PIN: '{}'", pin);

                // Compute client public key
                let a_pub = srp_client.compute_public_ephemeral(&a);
                tracing::debug!("Client PubKey (A) length: {}", a_pub.len());

                // Process server reply to get session key
                let srp_session = srp_client
                    .process_reply(&a, PAIR_SETUP, pin.as_bytes(), s, b_pub)
                    .map_err(|_| IdeviceError::UnexpectedResponse)?;

                // Store session key for later use
                srp_key = Some(srp_session.key().to_vec());

                // Get client proof from session (clone into owned Vec so we can move session)
                let client_proof = srp_session.proof().to_vec();
                tracing::debug!("Client proof length: {}", client_proof.len());

                // Store verifier so it can be used in state 4 to call verify_server
                srp_verifier = Some(srp_session);

                tlv.append(0x03, &a_pub); // Public key
                tlv.append(0x04, &client_proof); // Proof
            } else if current_state == 5 {
                // State 5: Send encrypted info
                let key = srp_key.as_ref().ok_or(IdeviceError::UnexpectedResponse)?;

                // Derive setup encryption key using HKDF
                let hk = Hkdf::<Sha512>::new(Some(PAIR_SETUP_ENCRYPT_SALT), key);
                hk.expand(PAIR_SETUP_ENCRYPT_INFO, &mut setup_encryption_key)
                    .map_err(|_| IdeviceError::UnexpectedResponse)?;

                // Generate Ed25519 keypair using ed25519-dalek's compatible RNG
                use rand_core::OsRng as CryptoOsRng;
                let ed_signing_key = SigningKey::generate(&mut CryptoOsRng);
                let ed_public_key = ed_signing_key.verifying_key();

                // Derive signature input using HKDF
                let mut sign_input = [0u8; 32];
                let hk = Hkdf::<Sha512>::new(Some(PAIR_SETUP_CONTROLLER_SIGN_SALT), key);
                hk.expand(PAIR_SETUP_CONTROLLER_SIGN_INFO, &mut sign_input)
                    .map_err(|_| IdeviceError::UnexpectedResponse)?;

                // Build signature buffer: HKDF output + pairing_uuid + ed25519_pubkey
                let mut signbuf = Vec::with_capacity(32 + pairing_uuid.len() + 32);
                signbuf.extend_from_slice(&sign_input);
                signbuf.extend_from_slice(pairing_uuid.as_bytes());
                signbuf.extend_from_slice(ed_public_key.as_bytes());

                // Sign
                let signature = ed_signing_key.sign(&signbuf);

                // Build inner TLV
                let mut inner_tlv = crate::utils::tlv::TlvBuf::new();
                inner_tlv.append(0x01, pairing_uuid.as_bytes()); // Identifier
                inner_tlv.append(0x03, ed_public_key.as_bytes()); // Public key
                inner_tlv.append(0x0A, signature.to_bytes().as_ref()); // Signature

                // ACL
                let acl_plist = match acl.clone() {
                    Some(a) => plist::Value::Dictionary(a),
                    None => {
                        let mut default_acl = plist::Dictionary::new();
                        default_acl.insert(
                            "com.apple.ScreenCapture".into(),
                            plist::Value::Boolean(true),
                        );
                        default_acl
                            .insert("com.apple.developer".into(), plist::Value::Boolean(true));
                        plist::Value::Dictionary(default_acl)
                    }
                };
                let acl_opack = crate::utils::opack::encode(&acl_plist);
                inner_tlv.append(0x12, &acl_opack);

                // Host info
                let hostname = hostname::get()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "RustHost".to_string());

                let mut host_info = plist::Dictionary::new();
                host_info.insert(
                    "accountID".into(),
                    plist::Value::String(pairing_uuid.clone()),
                );
                host_info.insert("model".into(), plist::Value::String(get_hardware_model()));
                host_info.insert("name".into(), plist::Value::String(hostname));
                host_info.insert("mac".into(), plist::Value::Data(get_local_mac()));

                // Print host_info as plist XML string for debugging
                let host_info_value = plist::Value::Dictionary(host_info);
                let mut host_info_xml = Vec::new();
                if host_info_value.to_writer_xml(&mut host_info_xml).is_ok() {
                    tracing::info!("Host info plist (XML): {}", String::from_utf8_lossy(&host_info_xml));
                }

                let host_info_opack = crate::utils::opack::encode(&host_info_value);
                inner_tlv.append(0x11, &host_info_opack);

                // Encrypt inner TLV with ChaCha20-Poly1305
                let cipher = ChaCha20Poly1305::new_from_slice(&setup_encryption_key)
                    .map_err(|_| IdeviceError::UnexpectedResponse)?;

                // Nonce for PS-Msg05 (8-byte nonce padded to 12 bytes)
                let mut nonce = [0u8; 12];
                nonce[4..12].copy_from_slice(b"PS-Msg05");

                let encrypted = cipher
                    .encrypt(&nonce.into(), inner_tlv.data())
                    .map_err(|_| IdeviceError::UnexpectedResponse)?;

                tlv.append(0x05, &encrypted);
            }

            tlv.append(0x06, &[current_state]); // State

            // Build request
            let payload = plist::Value::Data(tlv.into_data());
            let flags = if current_state == 1 { 1u64 } else { 0u64 };

            let req = crate::plist!({
                "Label": self.idevice.label.clone(),
                "Request": "CUPairingCreate",
                "Flags": flags,
                "Payload": payload,
                "ProtocolVersion": "2"
            });

            self.idevice.send_plist(req).await?;

            current_state += 1;

            let response = self.idevice.read_plist().await?;

            // Check for ExtendedResponse
            let ext_resp = response
                .get("ExtendedResponse")
                .and_then(|v| v.as_dictionary())
                .ok_or(IdeviceError::UnexpectedResponse)?;

            let payload_data = ext_resp
                .get("Payload")
                .and_then(|v| v.as_data())
                .ok_or(IdeviceError::UnexpectedResponse)?;

            // Parse TLV response
            let resp_state = crate::utils::tlv::tlv_get_uint8(payload_data, 0x06)
                .ok_or(IdeviceError::UnexpectedResponse)?;

            if resp_state != current_state {
                tracing::error!("Unexpected state {resp_state}, expected {current_state}");
                return Err(IdeviceError::UnexpectedResponse);
            }

            // Check for error
            if let Some(err) = crate::utils::tlv::tlv_get_uint(payload_data, 0x07) && err > 0 {
                if err == 2 && current_state == 4 {
                    tracing::error!("Invalid PIN");
                } else if err == 3 && let Some(delay) = crate::utils::tlv::tlv_get_uint(payload_data, 0x08) {
                    tracing::error!("Pairing blocked for {delay} seconds");
                }
                return Err(IdeviceError::UnexpectedResponse);
            }

            if current_state == 2 {
                // Receive salt and public key
                salt = crate::utils::tlv::tlv_get_data(payload_data, 0x02);
                server_pubkey = crate::utils::tlv::tlv_get_data(payload_data, 0x03);

                if salt.is_none() || server_pubkey.is_none() {
                    tracing::error!("Missing salt or public key in state 2");
                    return Err(IdeviceError::UnexpectedResponse);
                }
            } else if current_state == 4 {
                // Verify server proof
                let proof = crate::utils::tlv::tlv_get_data(payload_data, 0x04)
                    .ok_or(IdeviceError::UnexpectedResponse)?;

                tracing::debug!("Server proof received, length: {}", proof.len());
                // Use the previously saved verifier to verify the server proof (verify_server consumes the verifier)
                if let Some(verifier) = srp_verifier.take() {
                    if let Err(e) = verifier.verify_server(&proof) {
                        tracing::error!("Server proof verification failed: {e:?}");
                        return Err(IdeviceError::UnexpectedResponse);
                    }
                    tracing::debug!("PIN verified successfully");
                } else {
                    tracing::warn!("No SRP verifier available to verify server proof");
                }
            } else if current_state == 6 {
                // Check success
                let srp_pair_result = ext_resp.get("doSRPPair").and_then(|v| v.as_string());

                if srp_pair_result != Some("succeed") {
                    tracing::error!("SRP pairing failed");
                    return Err(IdeviceError::UnexpectedResponse);
                }

                // Decrypt device info
                if let Some(encrypted_data) = crate::utils::tlv::tlv_get_data(payload_data, 0x05) {
                    let cipher = ChaCha20Poly1305::new_from_slice(&setup_encryption_key)
                        .map_err(|_| IdeviceError::UnexpectedResponse)?;

                    let mut nonce = [0u8; 12];
                    nonce[4..12].copy_from_slice(b"PS-Msg06");

                    if let Ok(decrypted) = cipher.decrypt(&nonce.into(), encrypted_data.as_ref())
                        && let Some(device_info_data) = crate::utils::tlv::tlv_get_data(&decrypted, 0x11)
                        && let Some(device_info) = crate::utils::opack::decode(&device_info_data) {
                            tracing::info!("Device info: {:?}", device_info);
                            if let plist::Value::Dictionary(d) = device_info {
                                device_info_value = Some(d);
                            } else {
                                tracing::warn!("Device info is not a dictionary, ignoring");
                            }
                        }
                }
            }
        }

        let key = srp_key.ok_or(IdeviceError::UnexpectedResponse)?;
        Ok((key, device_info_value))
    }

    /// Creates a pairing record after successful CU pairing.
    /// Call this after `cu_pairing_create` succeeds.
    ///
    /// # Arguments
    /// * `cu_key` - The SRP key returned from `cu_pairing_create`
    /// * `host_id` - The host ID for the pairing file
    /// * `system_buid` - The system BUID
    ///
    /// # Returns
    /// A pairing file on success
    #[cfg(all(feature = "pair", feature = "rustls"))]
    pub async fn pair_cu(
        &mut self,
        cu_key: &[u8],
        host_id: impl Into<String>,
        system_buid: impl Into<String>,
    ) -> Result<crate::pairing_file::PairingFile, IdeviceError> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        use hkdf::Hkdf;
        use rand::RngCore;
        use sha2::Sha512;

        let host_id = host_id.into();
        let system_buid = system_buid.into();

        // Derive encryption keys
        const WRITE_KEY_SALT: &[u8] = b"WriteKeySaltMDLD";
        const WRITE_KEY_INFO: &[u8] = b"WriteKeyInfoMDLD";
        const READ_KEY_SALT: &[u8] = b"ReadKeySaltMDLD";
        const READ_KEY_INFO: &[u8] = b"ReadKeyInfoMDLD";

        let mut write_key = [0u8; 32];
        let mut read_key = [0u8; 32];

        let hk = Hkdf::<Sha512>::new(Some(WRITE_KEY_SALT), cu_key);
        hk.expand(WRITE_KEY_INFO, &mut write_key)
            .map_err(|_| IdeviceError::UnexpectedResponse)?;

        let hk = Hkdf::<Sha512>::new(Some(READ_KEY_SALT), cu_key);
        hk.expand(READ_KEY_INFO, &mut read_key)
            .map_err(|_| IdeviceError::UnexpectedResponse)?;

        let mut rng = rand::rng();

        // Get WiFiAddress
        let wifi_mac = {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);

            let payload = crate::plist!(dict { "Key": "WiFiAddress" });
            let mut buf = Vec::new();
            plist::Value::Dictionary(payload).to_writer_binary(&mut buf)?;

            let cipher = ChaCha20Poly1305::new_from_slice(&write_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let encrypted = cipher
                .encrypt(&nonce.into(), buf.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let req = crate::plist!({
                "Label": self.idevice.label.clone(),
                "Request": "GetValueCU",
                "Payload": plist::Value::Data(encrypted),
                "Nonce": plist::Value::Data(nonce.to_vec()),
                "ProtocolVersion": "2"
            });

            self.idevice.send_plist(req).await?;
            let response = self.idevice.read_plist().await?;

            let enc_payload = response
                .get("Payload")
                .and_then(|v| v.as_data())
                .ok_or(IdeviceError::UnexpectedResponse)?;

            let resp_nonce: [u8; 12] = response
                .get("Nonce")
                .and_then(|v| v.as_data())
                .and_then(|d| d.as_ref().try_into().ok())
                .unwrap_or(*b"receiveone01");

            let cipher = ChaCha20Poly1305::new_from_slice(&read_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let decrypted = cipher
                .decrypt(&resp_nonce.into(), enc_payload.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let result: plist::Dictionary = plist::from_bytes(&decrypted)?;
            result
                .get("Value")
                .and_then(|v| v.as_string())
                .ok_or(IdeviceError::UnexpectedResponse)?
                .to_string()
        };

        // Get DevicePublicKey
        let pub_key = {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);

            let payload = crate::plist!(dict { "Key": "DevicePublicKey" });
            let mut buf = Vec::new();
            plist::Value::Dictionary(payload).to_writer_binary(&mut buf)?;

            let cipher = ChaCha20Poly1305::new_from_slice(&write_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let encrypted = cipher
                .encrypt(&nonce.into(), buf.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let req = crate::plist!({
                "Label": self.idevice.label.clone(),
                "Request": "GetValueCU",
                "Payload": plist::Value::Data(encrypted),
                "Nonce": plist::Value::Data(nonce.to_vec()),
                "ProtocolVersion": "2"
            });

            self.idevice.send_plist(req).await?;
            let response = self.idevice.read_plist().await?;

            let enc_payload = response
                .get("Payload")
                .and_then(|v| v.as_data())
                .ok_or(IdeviceError::UnexpectedResponse)?;

            let resp_nonce: [u8; 12] = response
                .get("Nonce")
                .and_then(|v| v.as_data())
                .and_then(|d| d.as_ref().try_into().ok())
                .unwrap_or(*b"receiveone01");

            let cipher = ChaCha20Poly1305::new_from_slice(&read_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let decrypted = cipher
                .decrypt(&resp_nonce.into(), enc_payload.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let result: plist::Dictionary = plist::from_bytes(&decrypted)?;
            result
                .get("Value")
                .and_then(|v| v.as_data())
                .ok_or(IdeviceError::UnexpectedResponse)?
                .to_vec()
        };

        // Generate certificates
        let ca = crate::ca::generate_certificates(&pub_key, None).map_err(|e| {
            tracing::error!("Failed to generate certificates: {e}");
            IdeviceError::UnexpectedResponse
        })?;

        // Build pair record
        let mut pair_record = crate::plist!(dict {
            "DevicePublicKey": pub_key.clone(),
            "DeviceCertificate": ca.dev_cert.clone(),
            "HostCertificate": ca.host_cert.clone(),
            "HostID": host_id.clone(),
            "RootCertificate": ca.host_cert.clone(),
            "SystemBUID": system_buid.clone(),
            "WiFiMACAddress": wifi_mac.clone(),
        });

        // Send PairCU request
        let pair_resp = {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);

            let request_pair_record = pair_record.clone();
            let payload = crate::plist!(dict {
                "PairRecord": plist::Value::Dictionary(request_pair_record),
                "PairingOptions": {
                    "ExtendedPairingErrors": true
                }
            });
            let mut buf = Vec::new();
            plist::Value::Dictionary(payload).to_writer_binary(&mut buf)?;

            let cipher = ChaCha20Poly1305::new_from_slice(&write_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let encrypted = cipher
                .encrypt(&nonce.into(), buf.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let req = crate::plist!({
                "Label": self.idevice.label.clone(),
                "Request": "PairCU",
                "Payload": plist::Value::Data(encrypted),
                "Nonce": plist::Value::Data(nonce.to_vec()),
                "ProtocolVersion": "2"
            });

            self.idevice.send_plist(req).await?;
            let response = self.idevice.read_plist().await?;

            let enc_payload = response
                .get("Payload")
                .and_then(|v| v.as_data())
                .ok_or(IdeviceError::UnexpectedResponse)?;

            let resp_nonce: [u8; 12] = response
                .get("Nonce")
                .and_then(|v| v.as_data())
                .and_then(|d| d.as_ref().try_into().ok())
                .unwrap_or(*b"receiveone01");

            let cipher = ChaCha20Poly1305::new_from_slice(&read_key)
                .map_err(|_| IdeviceError::UnexpectedResponse)?;
            let decrypted = cipher
                .decrypt(&resp_nonce.into(), enc_payload.as_ref())
                .map_err(|_| IdeviceError::UnexpectedResponse)?;

            let result: plist::Dictionary = plist::from_bytes(&decrypted)?;
            result
        };

        // Add private keys and escrow bag
        pair_record.insert(
            "HostPrivateKey".into(),
            plist::Value::Data(ca.private_key.clone()),
        );
        pair_record.insert(
            "RootPrivateKey".into(),
            plist::Value::Data(ca.private_key),
        );

        if let Some(escrow) = pair_resp.get("EscrowBag").and_then(|v| v.as_data()) {
            pair_record.insert(
                "EscrowBag".into(),
                plist::Value::Data(escrow.to_vec()),
            );
        }

        let pairing_file =
            crate::pairing_file::PairingFile::from_value(&plist::Value::Dictionary(pair_record))?;

        Ok(pairing_file)
    }
}

/// Try to obtain a local MAC address.
/// On macOS this tries `ifconfig en0` first, then falls back to `ifconfig`.
#[allow(dead_code)]
fn get_local_mac() -> Vec<u8> {
    // Use `mac_address` crate only; if unavailable, return zeros.
    if let Ok(Some(ma)) = mac_address::get_mac_address() {
        let s = ma.to_string();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() >= 6 {
            let mut mac = Vec::with_capacity(6);
            let mut ok = true;
            for part in parts.iter().take(6) {
                match u8::from_str_radix(part.trim(), 16) {
                    Ok(b) => mac.push(b),
                    Err(_) => { ok = false; break; }
                }
            }
            if ok {
                return mac;
            }
        }
    }

    vec![0u8; 6]
}

impl From<Idevice> for LockdownClient {
    /// Converts an existing device connection into a lockdown client
    fn from(value: Idevice) -> Self {
        Self::new(value)
    }
}

fn get_hardware_model() -> String {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CStr;
        use std::os::raw::{c_char, c_void};

        unsafe extern "C" {
            fn sysctlbyname(
                name: *const c_char,
                oldp: *mut c_void,
                oldlenp: *mut usize,
                newp: *mut c_void,
                newlen: usize,
            ) -> i32;
        }

        let mut size = 0;
        let name = b"hw.model\0";
        unsafe {
            sysctlbyname(
                name.as_ptr() as *const c_char,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            );
        }

        if size > 0 {
            let mut buf = vec![0u8; size];
            unsafe {
                if sysctlbyname(
                    name.as_ptr() as *const c_char,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                ) == 0 && let Ok(s) = CStr::from_ptr(buf.as_ptr() as *const c_char).to_str() {
                    return s.to_string();
                }
            }
        }
    }

    "HackbookPro13,37".to_string()
}
