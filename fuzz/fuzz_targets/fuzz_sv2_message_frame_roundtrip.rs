#![no_main]

mod common;
mod generators;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use codec_sv2::SerializedFrame;
use common_messages_sv2;
use framing_sv2::header::Header;
use job_declaration_sv2;
use libfuzzer_sys::fuzz_target;
use mining_sv2;
use template_distribution_sv2;

const CHANNEL_MSG_MASK: u16 = 0b1000_0000_0000_0000;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    // Raw, unconstrained frame bytes: exercise the parser on arbitrary input.
    Raw(Vec<u8>),
    SetupConnection(Vec<u8>),
    SetupConnectionError(Vec<u8>),
    SetupConnectionSuccess(Vec<u8>),
    Reconnect(Vec<u8>),
    ChannelEndpointChanged(Vec<u8>),
    AllocateMiningJobToken(Vec<u8>),
    AllocateMiningJobTokenSuccess(Vec<u8>),
    DeclareMiningJob(Vec<u8>),
    DeclareMiningJobSuccess(Vec<u8>),
    DeclareMiningJobError(Vec<u8>),
    ProvideMissingTransactions(Vec<u8>),
    ProvideMissingTransactionsSuccess(Vec<u8>),
    PushSolution(Vec<u8>),
    CloseChannel(Vec<u8>),
    NewMiningJob(Vec<u8>),
    NewExtendedMiningJob(Vec<u8>),
    OpenStandardMiningChannel(Vec<u8>),
    OpenStandardMiningChannelSuccess(Vec<u8>),
    OpenExtendedMiningChannel(Vec<u8>),
    OpenExtendedMiningChannelSuccess(Vec<u8>),
    OpenMiningChannelError(Vec<u8>),
    SetCustomMiningJob(Vec<u8>),
    SetCustomMiningJobSuccess(Vec<u8>),
    SetCustomMiningJobError(Vec<u8>),
    SetExtranoncePrefix(Vec<u8>),
    SetGroupChannel(Vec<u8>),
    SetNewPrevHashMining(Vec<u8>),
    SetTarget(Vec<u8>),
    SubmitSharesStandard(Vec<u8>),
    SubmitSharesExtended(Vec<u8>),
    SubmitSharesSuccess(Vec<u8>),
    SubmitSharesError(Vec<u8>),
    UpdateChannel(Vec<u8>),
    UpdateChannelError(Vec<u8>),
    CoinbaseOutputConstraints(Vec<u8>),
    NewTemplate(Vec<u8>),
    RequestTransactionData(Vec<u8>),
    RequestTransactionDataSuccess(Vec<u8>),
    RequestTransactionDataError(Vec<u8>),
    SetNewPrevHashTemplate(Vec<u8>),
    SubmitSolution(Vec<u8>),
}

fn frame_bytes(payload: &[u8], msg_type: u8, channel_bit: bool) -> Vec<u8> {
    let extension_type: u16 = 0;
    let wire_extension_type = if channel_bit {
        extension_type | CHANNEL_MSG_MASK
    } else {
        extension_type & !CHANNEL_MSG_MASK
    };
    let payload_length = payload.len();
    let mut frame = Vec::with_capacity(6 + payload_length);
    frame.extend_from_slice(&wire_extension_type.to_le_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(&(payload_length as u32).to_le_bytes()[..3]);
    frame.extend_from_slice(payload);
    frame
}

fn run_raw(data: &[u8]) {
    // Direct frame path.
    if let Ok(mut frame) = SerializedFrame::from_bytes(data.to_vec().into()) {
        let header = frame.header();
        let payload_len = frame.payload().len();
        let mut payload = vec![0u8; payload_len];
        payload.copy_from_slice(frame.payload());
        let _ = common::check_parsed_message(header, &mut payload, None, &[]);
    }
    // Header-only parse path.
    let _ = Header::from_bytes(data);
}

fn run_generated(frame_bytes: &[u8], canonical: &[u8]) {
    if let Ok(mut frame) = SerializedFrame::from_bytes(frame_bytes.to_vec().into()) {
        let header = frame.header();
        let payload_len = frame.payload().len();
        let mut payload = vec![0u8; payload_len];
        payload.copy_from_slice(frame.payload());
        let _ = common::check_parsed_message(header, &mut payload, Some(canonical), &[]);
    }
    let _ = Header::from_bytes(frame_bytes);
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::Raw(data) => run_raw(&data),
        FuzzInput::SetupConnection(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_setup_connection(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION,
                    common_messages_sv2::CHANNEL_BIT_SETUP_CONNECTION,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetupConnectionError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_setup_connection_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
                    common_messages_sv2::CHANNEL_BIT_SETUP_CONNECTION_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetupConnectionSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_setup_connection_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                    common_messages_sv2::CHANNEL_BIT_SETUP_CONNECTION_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::Reconnect(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_reconnect(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    common_messages_sv2::MESSAGE_TYPE_RECONNECT,
                    common_messages_sv2::CHANNEL_BIT_RECONNECT,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::ChannelEndpointChanged(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_channel_endpoint_changed(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    common_messages_sv2::MESSAGE_TYPE_CHANNEL_ENDPOINT_CHANGED,
                    common_messages_sv2::CHANNEL_BIT_CHANNEL_ENDPOINT_CHANGED,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::AllocateMiningJobToken(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_allocate_mining_job_token(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
                    job_declaration_sv2::CHANNEL_BIT_ALLOCATE_MINING_JOB_TOKEN,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::AllocateMiningJobTokenSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_allocate_mining_job_token_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS,
                    job_declaration_sv2::CHANNEL_BIT_ALLOCATE_MINING_JOB_TOKEN_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::DeclareMiningJob(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_declare_mining_job(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_DECLARE_MINING_JOB,
                    job_declaration_sv2::CHANNEL_BIT_DECLARE_MINING_JOB,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::DeclareMiningJobSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_declare_mining_job_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS,
                    job_declaration_sv2::CHANNEL_BIT_DECLARE_MINING_JOB_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::DeclareMiningJobError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_declare_mining_job_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_DECLARE_MINING_JOB_ERROR,
                    job_declaration_sv2::CHANNEL_BIT_DECLARE_MINING_JOB_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::ProvideMissingTransactions(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_provide_missing_transactions(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS,
                    job_declaration_sv2::CHANNEL_BIT_PROVIDE_MISSING_TRANSACTIONS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::ProvideMissingTransactionsSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_provide_missing_transactions_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
                    job_declaration_sv2::CHANNEL_BIT_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::PushSolution(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_push_solution(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    job_declaration_sv2::MESSAGE_TYPE_PUSH_SOLUTION,
                    job_declaration_sv2::CHANNEL_BIT_PUSH_SOLUTION,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::CloseChannel(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_close_channel(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_CLOSE_CHANNEL,
                    mining_sv2::CHANNEL_BIT_CLOSE_CHANNEL,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::NewMiningJob(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_new_mining_job(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_NEW_MINING_JOB,
                    mining_sv2::CHANNEL_BIT_NEW_MINING_JOB,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::NewExtendedMiningJob(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_new_extended_mining_job(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                    mining_sv2::CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::OpenStandardMiningChannel(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_open_standard_mining_channel(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
                    mining_sv2::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::OpenStandardMiningChannelSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_open_standard_mining_channel_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                    mining_sv2::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::OpenExtendedMiningChannel(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_open_extended_mining_channel(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                    mining_sv2::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::OpenExtendedMiningChannelSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_open_extended_mining_channel_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                    mining_sv2::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::OpenMiningChannelError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_open_mining_channel_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
                    mining_sv2::CHANNEL_BIT_OPEN_MINING_CHANNEL_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetCustomMiningJob(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_custom_mining_job(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
                    mining_sv2::CHANNEL_BIT_SET_CUSTOM_MINING_JOB,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetCustomMiningJobSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_custom_mining_job_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
                    mining_sv2::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetCustomMiningJobError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_custom_mining_job_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
                    mining_sv2::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetExtranoncePrefix(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_extranonce_prefix(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX,
                    mining_sv2::CHANNEL_BIT_SET_EXTRANONCE_PREFIX,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetGroupChannel(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_group_channel(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_GROUP_CHANNEL,
                    mining_sv2::CHANNEL_BIT_SET_GROUP_CHANNEL,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetNewPrevHashMining(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_new_prev_hash_mining(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                    mining_sv2::CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetTarget(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_target(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SET_TARGET,
                    mining_sv2::CHANNEL_BIT_SET_TARGET,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SubmitSharesStandard(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_submit_shares_standard(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
                    mining_sv2::CHANNEL_BIT_SUBMIT_SHARES_STANDARD,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SubmitSharesExtended(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_submit_shares_extended(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
                    mining_sv2::CHANNEL_BIT_SUBMIT_SHARES_EXTENDED,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SubmitSharesSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_submit_shares_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
                    mining_sv2::CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SubmitSharesError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_submit_shares_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
                    mining_sv2::CHANNEL_BIT_SUBMIT_SHARES_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::UpdateChannel(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_update_channel(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_UPDATE_CHANNEL,
                    mining_sv2::CHANNEL_BIT_UPDATE_CHANNEL,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::UpdateChannelError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_update_channel_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    mining_sv2::MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
                    mining_sv2::CHANNEL_BIT_UPDATE_CHANNEL_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::CoinbaseOutputConstraints(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_coinbase_output_constraints(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
                    template_distribution_sv2::CHANNEL_BIT_COINBASE_OUTPUT_CONSTRAINTS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::NewTemplate(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_new_template(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_NEW_TEMPLATE,
                    template_distribution_sv2::CHANNEL_BIT_NEW_TEMPLATE,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::RequestTransactionData(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_request_transaction_data(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA,
                    template_distribution_sv2::CHANNEL_BIT_REQUEST_TRANSACTION_DATA,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::RequestTransactionDataSuccess(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_request_transaction_data_success(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                    template_distribution_sv2::CHANNEL_BIT_REQUEST_TRANSACTION_DATA_SUCCESS,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::RequestTransactionDataError(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_request_transaction_data_error(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
                    template_distribution_sv2::CHANNEL_BIT_REQUEST_TRANSACTION_DATA_ERROR,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SetNewPrevHashTemplate(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_set_new_prev_hash_template(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_SET_NEW_PREV_HASH,
                    template_distribution_sv2::CHANNEL_BIT_SET_NEW_PREV_HASH,
                );
                run_generated(&fb, &payload);
            }
        }
        FuzzInput::SubmitSolution(data) => {
            let mut u = Unstructured::new(&data);
            if let Ok(payload) = generators::gen_submit_solution(&mut u) {
                let fb = frame_bytes(
                    &payload,
                    template_distribution_sv2::MESSAGE_TYPE_SUBMIT_SOLUTION,
                    template_distribution_sv2::CHANNEL_BIT_SUBMIT_SOLUTION,
                );
                run_generated(&fb, &payload);
            }
        }
    }
});