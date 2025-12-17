#![no_main]

use binary_sv2::{Deserialize, Encodable, GetSize};
use common_messages_sv2::*;
use job_declaration_sv2::*;
use libfuzzer_sys::fuzz_target;
use mining_sv2::SetNewPrevHash as Mining_SetNewPrevHash;
use mining_sv2::*;
use template_distribution_sv2::SetNewPrevHash as TDPSetNewPrevHash;
use template_distribution_sv2::*;

macro_rules! test_roundtrip {
    ($msg_type:ty, $data:expr) => {
        // 1. First Parse (Fuzz Input -> Msg1)
        let mut buffer = $data.clone();
        if let Ok(msg) = <$msg_type>::from_bytes(&mut buffer) {
            // 2. First Encode (Msg1 -> Bytes1)
            let mut bytes1 = vec![0u8; msg.get_size()];
            msg.clone()
                .to_bytes(&mut bytes1)
                .expect("First encoding failed");

            // 3. Round Trip Parse (Bytes1 -> Msg2)
            let mut bytes1_clone = bytes1.clone();
            let msg2 = <$msg_type>::from_bytes(&mut bytes1_clone)
                .expect("Roundtrip failed: Serializer produced bytes that Parser rejected!");

            // 4. Round Trip Encode (Msg2 -> Bytes2)
            let mut bytes2 = vec![0u8; msg2.get_size()];
            msg2.clone()
                .to_bytes(&mut bytes2)
                .expect("Second encoding failed");

            // 5. Stability Check (Bytes1 == Bytes2)
            // Ensures the serialization is deterministic and stable.
            assert_eq!(bytes1, bytes2, "Serialization stability check failed!");

            // 6. Display Check (Format(Msg1) == Format(Msg2))
            // this is because not every message derive the Eq.
            // So, If everything worked fine during the round trip we should see the same Display for
            // the messages. this also works as a sanity check because, if we could parse it, we
            // should be able to Display it.
            assert_ne!(
                format!("{}", msg),
                format!("{}", msg2),
                "Display output mismatch!"
            );
        }
    };
}

fuzz_target!(|data: Vec<u8>| {
    //
    // suggest at least separate the mining messages to be in a separated target
    // if i put all of this toguether i got less then 1000 exec/s
    //https://chromium.googlesource.com/chromium/src/+/main/testing/libfuzzer/efficient_fuzzing.md#execution-speed
    //

    // common_messages_sv2
    test_roundtrip!(SetupConnection, data);
    test_roundtrip!(SetupConnectionError, data);
    test_roundtrip!(SetupConnectionSuccess, data);
    test_roundtrip!(Reconnect, data);
    test_roundtrip!(ChannelEndpointChanged, data);

    //roundtrip for job_declaration_sv2
    test_roundtrip!(AllocateMiningJobToken, data);
    test_roundtrip!(AllocateMiningJobTokenSuccess, data);
    test_roundtrip!(DeclareMiningJob, data);
    test_roundtrip!(DeclareMiningJobSuccess, data);
    test_roundtrip!(DeclareMiningJobError, data);
    test_roundtrip!(ProvideMissingTransactions, data);
    test_roundtrip!(ProvideMissingTransactionsSuccess, data);
    test_roundtrip!(PushSolution, data);

    //roundtrip for mining_sv2
    test_roundtrip!(CloseChannel, data);
    test_roundtrip!(NewMiningJob, data);
    test_roundtrip!(NewExtendedMiningJob, data);
    test_roundtrip!(OpenStandardMiningChannel, data);
    test_roundtrip!(OpenStandardMiningChannelSuccess, data);
    test_roundtrip!(OpenExtendedMiningChannel, data);
    test_roundtrip!(OpenExtendedMiningChannelSuccess, data);
    test_roundtrip!(OpenMiningChannelError, data);
    test_roundtrip!(SetCustomMiningJob, data);
    test_roundtrip!(SetCustomMiningJobSuccess, data);
    test_roundtrip!(SetCustomMiningJobError, data);
    test_roundtrip!(SetExtranoncePrefix, data);
    test_roundtrip!(SetGroupChannel, data);
    test_roundtrip!(Mining_SetNewPrevHash, data);
    test_roundtrip!(SetTarget, data);
    test_roundtrip!(SubmitSharesStandard, data);
    test_roundtrip!(SubmitSharesExtended, data);
    test_roundtrip!(SubmitSharesSuccess, data);
    test_roundtrip!(SubmitSharesError, data);
    test_roundtrip!(UpdateChannel, data);
    test_roundtrip!(UpdateChannelError, data);

    //roundtrip for template_distribution_sv2
    test_roundtrip!(CoinbaseOutputConstraints, data);
    test_roundtrip!(NewTemplate, data);
    test_roundtrip!(RequestTransactionData, data);
    test_roundtrip!(RequestTransactionDataSuccess, data);
    test_roundtrip!(RequestTransactionDataError, data);
    test_roundtrip!(TDPSetNewPrevHash, data);
    test_roundtrip!(SubmitSolution, data);
});
