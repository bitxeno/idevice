// Jackson Coxson
// Inspired by pymobiledevice3

use std::str::FromStr;

use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPublicKey,
    pkcs1v15::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding, SubjectPublicKeyInfo},
};
use sha2::Sha256;
use openssl::{asn1::Asn1Time, bn::BigNum, hash::MessageDigest, nid::Nid, pkey::PKey, x509::extension::{BasicConstraints, KeyUsage}, x509::X509Builder, x509::X509NameBuilder};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::EncodePem,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

#[derive(Clone, Debug)]
pub struct CaReturn {
    pub host_cert: Vec<u8>,
    pub dev_cert: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct CertConfig<'a> {
    pub profile: Profile,
    pub signing_key: &'a RsaPrivateKey,
    pub public_key: &'a RsaPublicKey,
    pub issuer_common_name: Option<&'a str>,
    pub common_name: Option<&'a str>,
    pub serial_bytes: Option<&'a [u8]>,
    pub use_sha1: bool,
    pub force_ca: Option<bool>,
    pub include_ski: Option<bool>,
}

pub fn make_cert(config: CertConfig) -> Result<String, Box<dyn std::error::Error>> {
    // Create subject/issuer name
    let name = match config.common_name {
        Some(name) => Name::from_str(&format!("CN={name}"))?,
        None => Name::default(),
    };

    // Set validity (10 years)
    let validity = Validity::from_now(std::time::Duration::from_secs(
        10 * 365 * 24 * 60 * 60,
    ))?;

    let public_key_spki = SubjectPublicKeyInfo::from_key(config.public_key.clone())?;

    let serial = match config.serial_bytes {
        Some(b) => SerialNumber::new(b)?,
        None => SerialNumber::new(&[1])?,
    };

    if config.use_sha1 {
        // Build certificate using OpenSSL to allow sha1WithRSAEncryption
        // Convert signing_key (rsa::RsaPrivateKey) to PKCS8 PEM and load into OpenSSL
        let priv_pem = config.signing_key.to_pkcs8_pem(LineEnding::LF)?;
        let pkey = PKey::private_key_from_pem(priv_pem.as_bytes())?;

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;

        // Serial
        if let Some(sb) = config.serial_bytes {
            let bn = BigNum::from_slice(sb)?;
            let asn1 = openssl::asn1::Asn1Integer::from_bn(&bn)?;
            builder.set_serial_number(&asn1)?;
        } else {
            let bn = BigNum::from_u32(1)?;
            let asn1 = openssl::asn1::Asn1Integer::from_bn(&bn)?;
            builder.set_serial_number(&asn1)?;
        }

            // Validity
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(3650)?;
            builder.set_not_before(&not_before)?;
            builder.set_not_after(&not_after)?;

        // Subject (empty or CN if provided)
        let mut subj_builder = X509NameBuilder::new()?;
        if let Some(cn) = config.common_name {
            subj_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
        }
        let subject_name = subj_builder.build();
        builder.set_subject_name(&subject_name)?;

        // Issuer: allow explicit issuer CN (None -> leave empty)
        let mut issuer_builder = X509NameBuilder::new()?;
        if let Some(icn) = config.issuer_common_name {
            issuer_builder.append_entry_by_nid(Nid::COMMONNAME, icn)?;
        }
        let issuer_name = issuer_builder.build();
        builder.set_issuer_name(&issuer_name)?;

        // Public key: try to convert public_key to PEM and load
        let pub_pem = public_key_spki.to_pem(LineEnding::LF)?;
        let pub_pkey = PKey::public_key_from_pem(pub_pem.as_bytes())?;
        builder.set_pubkey(&pub_pkey)?;

        // Basic constraints & key usage
        let is_ca = config.force_ca.unwrap_or(matches!(config.profile, Profile::Root));
        if is_ca {
            let bc = BasicConstraints::new().critical().ca().build()?;
            builder.append_extension(bc)?;
            let ku = KeyUsage::new().critical().key_cert_sign().crl_sign().build()?;
            builder.append_extension(ku)?;
        } else {
            let bc = BasicConstraints::new().critical().build()?;
            builder.append_extension(bc)?;
            let ku = KeyUsage::new().critical().digital_signature().key_encipherment().build()?;
            builder.append_extension(ku)?;
        }

        // Optionally add Subject Key Identifier (use public key)
        if config.include_ski.unwrap_or(false) {
            let ctx = builder.x509v3_context(None, None);
            let ski = openssl::x509::extension::SubjectKeyIdentifier::new().build(&ctx)?;
            builder.append_extension(ski)?;
        }

        builder.sign(&pkey, MessageDigest::sha1())?;
        let x509 = builder.build();
        let pem = x509.to_pem()?;
        Ok(String::from_utf8(pem)?)
    } else {
        let signing_key = SigningKey::<Sha256>::new(config.signing_key.clone());
        let cert = CertificateBuilder::new(config.profile, serial, validity, name, public_key_spki, &signing_key)?;
        let tbs_cert = cert.build()?;
        let pem = tbs_cert.to_pem(LineEnding::LF)?;
        Ok(pem)
    }
}

// Note: certificates are returned as PEM strings from `make_cert`.

pub(crate) fn generate_certificates(
    device_public_key_pem: &[u8],
    private_key: Option<RsaPrivateKey>,
) -> Result<CaReturn, Box<dyn std::error::Error>> {
    // Load device public key
    let device_public_key =
        RsaPublicKey::from_pkcs1_pem(std::str::from_utf8(device_public_key_pem)?)?;

    // Generate or use provided private key
    let private_key = match private_key {
        Some(p) => p,
        None => {
            let mut rng = rsa::rand_core::OsRng;
            RsaPrivateKey::new(&mut rng, 2048)?
        }
    };

    // Create CA cert
    let ca_public_key = RsaPublicKey::from(&private_key);
    let ca_cert = make_cert(CertConfig {
        profile: Profile::Root,
        signing_key: &private_key,
        public_key: &ca_public_key,
        issuer_common_name: None,
        common_name: None,
        serial_bytes: None,
        use_sha1: false,
        force_ca: None,
        include_ski: None,
    })?;

    // Create device cert (signed by CA)
    let dev_cert = make_cert(CertConfig {
        profile: Profile::Root,
        signing_key: &private_key,
        public_key: &device_public_key,
        issuer_common_name: None,
        common_name: Some("Device"),
        serial_bytes: None,
        use_sha1: false,
        force_ca: None,
        include_ski: None,
    })?;

    Ok(CaReturn {
        host_cert: ca_cert.into_bytes(),
        dev_cert: dev_cert.into_bytes(),
        private_key: private_key
            .to_pkcs8_pem(LineEnding::LF)?
            .as_bytes()
            .to_vec(),
    })
}

#[derive(Clone, Debug)]
pub struct CaReturnCu {
    pub dev_cert: Vec<u8>,
    pub host_key: Vec<u8>,
    pub host_cert: Vec<u8>,
    pub root_key: Vec<u8>,
    pub root_cert: Vec<u8>,
}

/// Generate root/host keys and certificates and sign the device certificate with the root.
/// Simplified: ignores device_version and pair_record, uses SHA-1 (EVP_Sha256).
pub fn generate_certificates_cu(
    device_public_key_pem: &[u8],
) -> Result<CaReturnCu, Box<dyn std::error::Error>> {
    // Load device public key
    let device_public_key = RsaPublicKey::from_pkcs1_pem(std::str::from_utf8(device_public_key_pem)?)?;

    // Generate root and host private keys
    let mut rng = rsa::rand_core::OsRng;
    let root_priv = RsaPrivateKey::new(&mut rng, 2048)?;
    let host_priv = RsaPrivateKey::new(&mut rng, 2048)?;

    let root_pub = RsaPublicKey::from(&root_priv);
    let host_pub = RsaPublicKey::from(&host_priv);

    // Create certificates (signing with root_priv)
    let root_cert = make_cert(CertConfig {
        profile: Profile::Root,
        signing_key: &root_priv,
        public_key: &root_pub,
        issuer_common_name: None,
        common_name: None,
        serial_bytes: Some(&[0u8]),
        use_sha1: true,
        force_ca: Some(true),
        include_ski: None,
    })?;
    let host_cert = make_cert(CertConfig {
        profile: Profile::Root,
        signing_key: &root_priv,
        public_key: &host_pub,
        issuer_common_name: None,
        common_name: None,
        serial_bytes: Some(&[0u8]),
        use_sha1: true,
        force_ca: Some(false),
        include_ski: None,
    })?;
    let dev_cert = make_cert(CertConfig {
        profile: Profile::Root,
        signing_key: &root_priv,
        public_key: &device_public_key,
        issuer_common_name: None,
        common_name: None,
        serial_bytes: Some(&[0u8]),
        use_sha1: true,
        force_ca: Some(false),
        include_ski: Some(true),
    })?;

    Ok(CaReturnCu {
        dev_cert: dev_cert.into_bytes(),
        host_key: host_priv.to_pkcs8_pem(LineEnding::LF)?.as_bytes().to_vec(),
        host_cert: host_cert.into_bytes(),
        root_key: root_priv.to_pkcs8_pem(LineEnding::LF)?.as_bytes().to_vec(),
        root_cert: root_cert.into_bytes(),
    })
}
