#![no_main]

use std::fmt::Display;

use binary_sv2::{Deserialize, Encodable, GetSize};
use common_messages_sv2::*;
use job_declaration_sv2::*;
use libfuzzer_sys::fuzz_target;
use mining_sv2::SetNewPrevHash as Mining_SetNewPrevHash;
use mining_sv2::*;
use template_distribution_sv2::SetNewPrevHash as TDPSetNewPrevHash;
use template_distribution_sv2::*;

fn test_serialization_roundtrip<'a, T>(fuzz_input: &'a mut [u8])
where
    T: Deserialize<'a> + Encodable + GetSize + Display + Clone,
{
    if let Ok(message) = T::from_bytes(fuzz_input) {
        let mut encoded = vec![0u8; message.get_size()];
        message.clone().to_bytes(&mut encoded).unwrap();

        //sanity check: if we were able to parse the message, we should also be able to Display it;
        let _ = format!("{message}");
    }
}

fuzz_target!(|data: Vec<u8>| {
    //some rationale backing this target: having to target multiple messages in the same target is
    //far from ideal and it is actually recommended by the libfuzzer docs that we narrow down the
    //target. See: https://llvm.org/docs/LibFuzzer.html#id23
    // But creating a target for each message can be cumbersome and a lot of unnecessary repetition
    // of codes. Google fuzzing guidelines suggests that for these case we could create a single
    // fuzz test for the parser (in our case the macros Serialize and Deserialize). This way we can
    // avoid doing a shallow fuzzing per message and target the parser itself, see: https://fuchsia.googlesource.com/fuchsia/%2B/20cc73a21f4bfe65e139cc54c61be0d7c03fc8cc/docs/development/workflows/libfuzzer.md?utm_source=chatgpt.com#q_how-should-i-scope-my-fuzz-targets
    // We also have to consider that our messages are basically constructed the same way by
    // deriving the Deserialize and Serialize macro, so we'd basically hit the same code paths by
    // doing the shallow fuzzing per message. In this way we continue to do the same sanity checks,
    // but with less targets to maintain

    //roundtrip for common_messages_sv2
    test_serialization_roundtrip::<SetupConnection>(&mut data.clone());
    test_serialization_roundtrip::<SetupConnectionError>(&mut data.clone());
    test_serialization_roundtrip::<SetupConnectionSuccess>(&mut data.clone());
    test_serialization_roundtrip::<Reconnect>(&mut data.clone());
    test_serialization_roundtrip::<ChannelEndpointChanged>(&mut data.clone());

    //roundtrip for job_declaration_sv2
    test_serialization_roundtrip::<AllocateMiningJobToken>(&mut data.clone());
    test_serialization_roundtrip::<AllocateMiningJobTokenSuccess>(&mut data.clone());
    test_serialization_roundtrip::<DeclareMiningJob>(&mut data.clone());
    test_serialization_roundtrip::<DeclareMiningJobSuccess>(&mut data.clone());
    test_serialization_roundtrip::<DeclareMiningJobError>(&mut data.clone());
    test_serialization_roundtrip::<ProvideMissingTransactions>(&mut data.clone());
    test_serialization_roundtrip::<ProvideMissingTransactionsSuccess>(&mut data.clone());
    test_serialization_roundtrip::<PushSolution>(&mut data.clone());

    //roundtrip for mining_sv2
    test_serialization_roundtrip::<CloseChannel>(&mut data.clone());
    test_serialization_roundtrip::<NewMiningJob>(&mut data.clone());
    test_serialization_roundtrip::<NewExtendedMiningJob>(&mut data.clone());
    test_serialization_roundtrip::<OpenStandardMiningChannel>(&mut data.clone());
    test_serialization_roundtrip::<OpenStandardMiningChannelSuccess>(&mut data.clone());
    test_serialization_roundtrip::<OpenExtendedMiningChannel>(&mut data.clone());
    test_serialization_roundtrip::<OpenExtendedMiningChannelSuccess>(&mut data.clone());
    test_serialization_roundtrip::<OpenMiningChannelError>(&mut data.clone());
    test_serialization_roundtrip::<SetCustomMiningJob>(&mut data.clone());
    test_serialization_roundtrip::<SetCustomMiningJobSuccess>(&mut data.clone());
    test_serialization_roundtrip::<SetCustomMiningJobError>(&mut data.clone());
    test_serialization_roundtrip::<SetExtranoncePrefix>(&mut data.clone());
    test_serialization_roundtrip::<SetGroupChannel>(&mut data.clone());
    test_serialization_roundtrip::<Mining_SetNewPrevHash>(&mut data.clone());
    test_serialization_roundtrip::<SetTarget>(&mut data.clone());
    test_serialization_roundtrip::<SubmitSharesStandard>(&mut data.clone());
    test_serialization_roundtrip::<SubmitSharesExtended>(&mut data.clone());
    test_serialization_roundtrip::<SubmitSharesSuccess>(&mut data.clone());
    test_serialization_roundtrip::<SubmitSharesError>(&mut data.clone());
    test_serialization_roundtrip::<UpdateChannel>(&mut data.clone());
    test_serialization_roundtrip::<UpdateChannelError>(&mut data.clone());

    //roundtrip for template_distribution_sv2
    test_serialization_roundtrip::<CoinbaseOutputConstraints>(&mut data.clone());
    test_serialization_roundtrip::<NewTemplate>(&mut data.clone());
    test_serialization_roundtrip::<RequestTransactionData>(&mut data.clone());
    test_serialization_roundtrip::<RequestTransactionDataSuccess>(&mut data.clone());
    test_serialization_roundtrip::<RequestTransactionDataError>(&mut data.clone());
    test_serialization_roundtrip::<TDPSetNewPrevHash>(&mut data.clone());
    test_serialization_roundtrip::<SubmitSolution>(&mut data.clone());
});
