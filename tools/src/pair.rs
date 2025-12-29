// Jackson Coxson

use clap::{Arg, Command};
use idevice::{
    IdeviceService,
    lockdown::LockdownClient,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let matches = Command::new("pair")
        .about("Pair with the device")
        .arg(
            Arg::new("udid")
                .value_name("UDID")
                .help("UDID of the device (overrides host/pairing file)")
                .index(1),
        )
        .arg(
            Arg::new("about")
                .long("about")
                .help("Show about information")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("wireless")
                .long("wireless")
                .help("Perform wireless pairing (e.g. for Apple TV)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    if matches.get_flag("about") {
        println!("pair - pair with the device");
        println!("Copyright (c) 2025 Jackson Coxson");
        return;
    }

    let udid = matches.get_one::<String>("udid");
    let wireless = matches.get_flag("wireless");

    let mut u = UsbmuxdConnection::default()
        .await
        .expect("Failed to connect to usbmuxd");

    // For wireless pairing, we might be connecting to a network device
    let dev = match udid {
        Some(udid) => u
            .get_device(udid)
            .await
            .expect("Failed to get device with specific udid"),
        None => {
            let devices = u.get_devices().await.expect("Failed to get devices");
            if wireless {
                // Filter for network devices
                devices
                    .into_iter()
                    .find(|x| matches!(x.connection_type, Connection::Network(_)))
                    .expect("No devices connected via Network")
            } else {
                devices
                    .into_iter()
                    .find(|x| x.connection_type == Connection::Usb)
                    .expect("No devices connected via USB")
            }
        }
    };
    let provider = dev.to_provider(UsbmuxdAddr::default(), "pair-jkcoxson");

    let mut lockdown_client = match LockdownClient::connect(&provider).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Unable to connect to lockdown: {e:?}");
            return;
        }
    };
    let id = u
        .get_buid()
        .await
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string().to_uppercase());
    let buid = id.clone();
    let mut s_udid = dev.udid.clone();

    let mut pairing_file = if wireless {
        println!("Starting wireless pairing...");

        let pin_cb = || async move {
            println!("Enter PIN:");
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            lines
                .next_line()
                .await
                .unwrap_or_default()
                .unwrap_or_default()
        };

        let (cu_key, device_info) = lockdown_client
            .cu_pairing_create(id.clone(), pin_cb, None)
            .await
            .expect("Failed to perform wireless pairing handshake");

        // Obtain the paired UDID from device info
        s_udid = device_info
            .as_ref()
            .and_then(|d| d.get("udid"))
            .and_then(|v| v.as_string())
            .expect("Failed to obtain UDID from device info")
            .to_string();

        lockdown_client
            .pair_cu(&cu_key, id, buid)
            .await
            .expect("Failed to create pairing record")
    } else {
        lockdown_client
            .pair(id, buid)
            .await
            .expect("Failed to pair")
    };

    // Test the pairing file
    lockdown_client
        .start_session(&pairing_file)
        .await
        .expect("Pairing file test failed");

    // Add the UDID (jitterbug spec)
    pairing_file.udid = Some(s_udid.clone());
    let pairing_file = pairing_file.serialize().expect("failed to serialize");

    println!("{}", String::from_utf8(pairing_file.clone()).unwrap());

    // Save with usbmuxd
    u.save_pair_record(&s_udid, pairing_file)
        .await
        .expect("no save");
}
