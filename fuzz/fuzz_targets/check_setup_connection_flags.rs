#![no_main]
use arbitrary::Arbitrary;
use binary_sv2::{Deserialize, Encodable, GetSize};
use common_messages_sv2::{Protocol, SetupConnection};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    protocol: u8,
    min_version: u16,
    max_version: u16,
    flags: u32,
    required_flags: u32,

    endpoint_host: Vec<u8>,
    endpoint_port: u16,
    vendor: Vec<u8>,
    hardware_version: Vec<u8>,
    firmware: Vec<u8>,
    device_id: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    // Normalize the protocol range
    let protocol = Protocol::try_from(input.protocol % 3).unwrap();

    let sc = SetupConnection {
        protocol,
        min_version: input.min_version,
        max_version: input.max_version,
        flags: input.flags,
        endpoint_host: input.endpoint_host.try_into().unwrap(),
        endpoint_port: input.endpoint_port,
        vendor: input.vendor.try_into().unwrap(),
        hardware_version: input.hardware_version.try_into().unwrap(),
        firmware: input.firmware.try_into().unwrap(),
        device_id: input.device_id.try_into().unwrap(),
    };

    // ✔ Check branches inside check_flags
    let _ = SetupConnection::check_flags(protocol, input.flags, input.required_flags);

    // ✔ Test the version negotiation logic
    let _ = sc.get_version(input.min_version, input.max_version);

    // ✔ Exercise flag helpers explicitly
    let _ = common_messages_sv2::has_requires_std_job(input.flags);
    let _ = common_messages_sv2::has_version_rolling(input.flags);
    let _ = common_messages_sv2::has_work_selection(input.flags);

    // ✔ Fuzz the Display impl (important for crash bugs)
    let _ = format!("{}", sc);

    // ✔ Feed the fields back through serialization/deserialization
    //    This triggers more internal paths.
    let mut buf = vec![0u8; sc.get_size()];
    let _ = sc.to_bytes(&mut buf);
    let _ = SetupConnection::from_bytes(&mut buf.clone());
});

