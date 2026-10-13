//! Modules implementing the FIX spec for [encoding] and [decoding] messages
//!
//! [encoding]: crate::fix::encode
//! [decoding]: crate::fix::decode

use chrono::naive::NaiveDateTime;
use chrono::{DateTime, Utc};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use anyhow::{bail, Result};
use thiserror::Error;

use crate::fix::decode::{parse_field, parse_sending_time};
use crate::fix::encode::{AdditionalHeaders, MessageBuilder, SerializedInt};
use crate::fix::generated::{GapFillFlag, PossDupFlag, SessionRejectReason, Tags};
use crate::fix::log::Logger;
use crate::fix::msg_type::MsgTypeBuf;
use crate::fix::resend::Transformer;
use crate::fix::session::{Event, MyStateMachine};
use crate::fix::stopwatch::FixTimeouts;
use crate::fix::validate::validate_msg;
use crate::{FixEngineType, InitiatorLogonContext, Request, SessionSettings};
use store::Store;

use generated::MsgType;
use generated::MsgType::*;
use mem::MsgBuf;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod decode;
pub mod encode;
pub mod generated;
pub mod log;
pub mod mem;

mod checksum;
pub(crate) mod msg_type;
mod resend;
mod session;
mod stopwatch;
mod stream;
mod validate;

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite_store;
#[cfg(feature = "sqlite")]
use sqlite_store as store;

#[cfg(not(feature = "sqlite"))]
mod vec_store;
#[cfg(not(feature = "sqlite"))]
use vec_store as store;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("An I/O error occured: {0}")]
    IoError(#[from] io::Error),
    #[error("A garbled message was received")]
    GarbledMessage {
        text: String,
        garbled_msg_type: GarbledMessageType,
    },
    #[error("A message was received without a sequence number")]
    MissingMsgSeqNum { text: String },
    #[error("A message was rejected because: {text}")]
    MessageRejected {
        text: String,
        reject_reason: Option<SessionRejectReason>,
        msg_seq_num: u32,
        ref_tag_id: Option<u32>,
        ref_msg_type: Option<String>,
    },
    #[error("Tried to resend a malformed message")]
    ResendError,
    #[error("TCP peer closed their half of the connection")]
    TcpDisconnection,
    #[error("failed to customize outbound logon: {0}")]
    LogonCustomize(String),
}

#[derive(Debug)]
pub enum GarbledMessageType {
    BeginStringIssue,
    BodyLengthIssue,
    MsgTypeIssue,
    ChecksumIssue,
    Other,
}

impl SessionError {
    fn new_message_rejected(
        reason: Option<SessionRejectReason>,
        seq_num: u32,
        tag_id: Option<u32>,
        msg_type: Option<MsgTypeBuf>,
    ) -> SessionError {
        SessionError::MessageRejected {
            text: reason.as_ref().map_or(String::from(""), |r| r.into()),
            reject_reason: reason,
            msg_seq_num: seq_num,
            ref_tag_id: tag_id,
            ref_msg_type: msg_type
                .filter(|t| !t.is_empty())
                .map(|t| t.as_str().to_owned()),
        }
    }

    fn new_garbled_message(text: String, t: GarbledMessageType) -> SessionError {
        SessionError::GarbledMessage {
            text,
            garbled_msg_type: t,
        }
    }
}

#[derive(Default)]
struct SessionParserCallback<'a> {
    msg_type: MsgTypeBuf,
    msg_seq_num: u32,
    sender_comp_id: Option<&'a [u8]>,
    target_comp_id: Option<&'a [u8]>,
    target_sub_id: Option<&'a [u8]>,
    poss_dup_flag: Option<char>,
    gap_fill: Option<char>,
    new_seq_no: Option<u32>,
    test_req_id: Option<&'a [u8]>,
    begin_seq_no: Option<u32>,
    end_seq_no: Option<u32>,
    heart_bt_int: Option<u32>,
    sending_time: Option<DateTime<Utc>>,
    orig_sending_time: Option<DateTime<Utc>>,
    encrypt_method: Option<u32>,
    reset_seq_num_flag: Option<char>,
}

impl<'a> crate::fix::decode::ParserCallback<'a> for SessionParserCallback<'a> {
    type Err = SessionError;
    fn header(&mut self, key: u32, value: &'a [u8]) -> Result<bool, Self::Err> {
        match key.try_into() {
            Ok(Tags::MsgType) => match MsgTypeBuf::from_bytes(value) {
                Some(msg_type) => self.msg_type = msg_type,
                None => {
                    return Err(self.create_message_reject(
                        SessionRejectReason::INVALID_MSGTYPE,
                        Tags::MsgType,
                    ));
                }
            },
            Ok(Tags::MsgSeqNum) => {
                self.msg_seq_num =
                    parse_field::<u32>(value).or(Err(SessionError::MissingMsgSeqNum {
                        text: String::from("Missing MsgSeqNum"),
                    }))?;
            }
            Ok(Tags::TargetCompID) => {
                self.target_comp_id = Some(value);
            }
            Ok(Tags::SenderCompID) => {
                self.sender_comp_id = Some(value);
            }
            Ok(Tags::TargetSubID) => {
                self.target_sub_id = Some(value);
            }
            Ok(Tags::PossDupFlag) => {
                if value.len() == 1 {
                    self.poss_dup_flag = Some(value[0] as char);
                } else {
                    return Err(self.create_message_reject(
                        SessionRejectReason::VALUE_IS_INCORRECT,
                        Tags::PossDupFlag,
                    ));
                }
            }
            Ok(Tags::SendingTime) => match parse_sending_time(value) {
                Ok(sending_time) => {
                    self.sending_time = Some(sending_time);
                }
                Err(_) => {
                    return Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::SendingTime,
                    ));
                }
            },
            Ok(Tags::OrigSendingTime) => match parse_sending_time(value) {
                Ok(sending_time) => {
                    self.orig_sending_time = Some(sending_time);
                }
                Err(_) => {
                    return Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::SendingTime,
                    ));
                }
            },
            _ => (),
        }
        Ok(true)
    }

    fn body(&mut self, key: u32, value: &'a [u8]) -> Result<bool, Self::Err> {
        if !self.msg_type.is_session() {
            return Ok(false);
        }
        match key.try_into() {
            Ok(Tags::GapFillFlag) => {
                if value.len() == 1 {
                    self.gap_fill = Some(value[0] as char);
                } else {
                    return Err(self.create_message_reject(
                        SessionRejectReason::VALUE_IS_INCORRECT,
                        Tags::GapFillFlag,
                    ));
                }
            }
            Ok(Tags::NewSeqNo) => {
                self.new_seq_no =
                    Some(parse_field::<u32>(value).or(Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::NewSeqNo,
                    )))?);
            }
            Ok(Tags::TestReqID) => {
                self.test_req_id = Some(value);
            }
            Ok(Tags::BeginSeqNo) => {
                self.begin_seq_no =
                    Some(parse_field::<u32>(value).or(Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::BeginSeqNo,
                    )))?);
            }
            Ok(Tags::EndSeqNo) => {
                self.end_seq_no =
                    Some(parse_field::<u32>(value).or(Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::EndSeqNo,
                    )))?);
            }
            Ok(Tags::HeartBtInt) => {
                self.heart_bt_int =
                    Some(parse_field::<u32>(value).or(Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::HeartBtInt,
                    )))?)
            }
            Ok(Tags::EncryptMethod) => {
                self.encrypt_method =
                    Some(parse_field::<u32>(value).or(Err(self.create_message_reject(
                        SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE,
                        Tags::EndSeqNo,
                    )))?);
            }
            Ok(Tags::ResetSeqNumFlag) => {
                if value.len() == 1 {
                    self.reset_seq_num_flag = Some(value[0] as char);
                } else {
                    return Err(self.create_message_reject(
                        SessionRejectReason::VALUE_IS_INCORRECT,
                        Tags::ResetSeqNumFlag,
                    ));
                }
            }
            _ => (),
        }
        Ok(true)
    }

    fn trailer(&mut self, _key: u32, _value: &'a [u8]) -> Result<bool, Self::Err> {
        Ok(false)
    }

    fn parse_error(&mut self, err: decode::MessageParseError) -> Result<(), Self::Err> {
        match err {
            decode::MessageParseError::BadLengthField(tag, _) => {
                Err(SessionError::new_message_rejected(
                    Some(SessionRejectReason::INCORRECT_DATA_FORMAT_FOR_VALUE),
                    self.msg_seq_num,
                    Some(tag),
                    None,
                ))
            }
            decode::MessageParseError::UnexpectedByte(..) => Err(SessionError::GarbledMessage {
                text: "invalid character in message".to_string(),
                garbled_msg_type: GarbledMessageType::Other,
            }),
        }
    }
}

impl SessionParserCallback<'_> {
    fn create_message_reject(&self, reason: SessionRejectReason, reg_tag: Tags) -> SessionError {
        SessionError::new_message_rejected(
            Some(reason),
            self.msg_seq_num,
            Some(reg_tag.into()),
            Some(self.msg_type),
        )
    }
}

pub(super) async fn spin_session<L>(
    mut stream: TcpStream,
    mut request_receiver: mpsc::UnboundedReceiver<Request>,
    message_received_event_sender: mpsc::UnboundedSender<Arc<MsgBuf>>,
    settings: SessionSettings,
    logger: L,
) -> Result<()>
where
    L: Logger + Send + Sync + 'static,
{
    // SETUP

    let additional_headers = AdditionalHeaders::build(&settings);
    let store = Store::build(&settings)?;
    let sequences = store.get_sequences(settings.epoch.clone()).await?;
    let mut state_machine = MyStateMachine::new(&settings, sequences);

    let logon_resp_sender = receive_logon_request(&mut request_receiver).await;

    let start_new_session = is_new_session(&store, &settings).await?;
    match settings.engine_type {
        FixEngineType::Server => {
            state_machine.set_logon_resp_sender(logon_resp_sender);
            state_machine.handle(&crate::fix::session::Event::Accept);
        }
        FixEngineType::Client => {
            state_machine.set_logon_resp_sender(logon_resp_sender);
            state_machine.handle(&crate::fix::session::Event::Connect(start_new_session));
        }
    }

    let epoch = settings.epoch.clone();
    let heartbt_dur = &settings.heartbeat_timeout;
    let tr_dur = test_request_duration(heartbt_dur);
    let logout_dur = logout_duration(heartbt_dur);
    let mut fix_timeouts = FixTimeouts::new(*heartbt_dur, tr_dur, logout_dur);

    let mut header_buf: stream::HeaderBuf<{ stream::PEEK_LEN }> = stream::HeaderBuf::new();

    // LOOP

    loop {
        send_outgoing_messages(
            &mut state_machine,
            &mut stream,
            &additional_headers,
            &settings,
            &store,
            Arc::clone(&epoch),
            &logger,
            &mut fix_timeouts,
        )
        .await?;

        if session::should_disconnect(&state_machine) {
            let resp = disconnect(
                request_receiver,
                store,
                epoch,
                &state_machine,
                stream,
                logger,
            )
            .await;
            let logout_success = !session::in_error_state(&state_machine);
            state_machine.send_logout_response(logout_success && resp.is_ok());
            resp?;
            break;
        }

        let next_timeout = fix_timeouts.next_expiring_timeout();
        let (timeout_fut, timeout_event) = next_timeout.timeout();

        tokio::select! {
            biased;

            maybe_err = stream::read_header(&mut stream, &mut header_buf) => {
                let maybe_message = match maybe_err {
                    Ok(()) => stream::read_message(&mut stream, &mut header_buf, &logger).await,
                    Err(SessionError::IoError(e)) => bail!("{e:?}"),
                    Err(e) => Err(e),
                };

                if let Err(SessionError::IoError(e)) = maybe_message {
                    bail!("{e:?}");
                }

                handle_msg(
                    maybe_message,
                    &mut state_machine,
                    &mut fix_timeouts,
                    &store,
                    &settings,
                    &mut stream,
                    &logger,
                    &additional_headers,
                    &message_received_event_sender,
                ).await?;
            }
            Some(req) = request_receiver.recv() => {
                handle_req(req, &mut state_machine, &store, &epoch);
            }
            _ = timeout_fut => {
                state_machine.handle(timeout_event);
                next_timeout.reset_timeout();
            }
        };
    }
    Ok(())
}

fn test_request_duration(timeout_dur: &Duration) -> Duration {
    (*timeout_dur * 17) / 10
}

fn logout_duration(timeout_dur: &Duration) -> Duration {
    *timeout_dur * 2
}

fn handle_req(
    req: Request,
    state_machine: &mut MyStateMachine,
    store: &Store,
    epoch: &Arc<String>,
) {
    match req {
        Request::SendMessage {
            resp_sender,
            builder,
        } => {
            state_machine.outbox_push_with_sender(builder, resp_sender);
        }
        Request::Logout { resp_sender } => {
            let begin_string = Arc::clone(&state_machine.begin_string);
            state_machine.outbox_push_with_sender(
                crate::fix::session::build_logout_message(&begin_string),
                resp_sender,
            );
        }
        Request::Logon { resp_sender } => {
            let _ = resp_sender.send(true);
        }
        Request::SetSequenceNumbers {
            resp_sender,
            next_outbound,
            expected_inbound,
        } => {
            // Set the sequence numbers directly in the state machine
            state_machine
                .sequences
                .set_both(next_outbound, expected_inbound);
            let result = store.set_sequences(Arc::clone(epoch), next_outbound, expected_inbound);
            if let Err(e) = &result {
                eprintln!("{e}: error setting sequence numbers");
            }
            let _ = resp_sender.send(result.is_ok());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_msg<L>(
    maybe_msg: Result<MsgBuf, SessionError>,
    state_machine: &mut MyStateMachine,
    fix_timeouts: &mut FixTimeouts,
    store: &Store,
    settings: &SessionSettings,
    stream: &mut TcpStream,
    logger: &L,
    additional_headers: &AdditionalHeaders,
    message_received_event_sender: &mpsc::UnboundedSender<Arc<MsgBuf>>,
) -> Result<()>
where
    L: Logger + Send + Sync,
{
    fix_timeouts.reset_test_request();

    let msg = match maybe_msg {
        Ok(b) => Arc::new(b),
        Err(error) => {
            state_machine.handle(&Event::SessionErrorReceived {
                error,
                poss_dup: None,
            });
            return Ok(());
        }
    };

    // PARSE

    let mut cb: SessionParserCallback = Default::default();

    if let Err(error) = crate::fix::decode::parse(&msg.as_ref()[..], &mut cb) {
        state_machine.handle(&Event::SessionErrorReceived {
            error,
            poss_dup: to_poss_dup_flag(cb.poss_dup_flag),
        });
        return Ok(());
    };

    // VALIDATE

    if let Err(error) = validate_msg(
        settings.expected_sender_comp_id(),
        settings.expected_target_comp_id(),
        settings.accepted_msg_types(),
        cb.msg_type,
        cb.msg_seq_num,
        cb.target_comp_id,
        cb.sender_comp_id,
        cb.target_sub_id,
        cb.sending_time,
        cb.poss_dup_flag,
        cb.orig_sending_time,
        cb.begin_seq_no,
        cb.end_seq_no,
    ) {
        state_machine.handle(&Event::SessionErrorReceived {
            error,
            poss_dup: to_poss_dup_flag(cb.poss_dup_flag),
        });
        return Ok(());
    }

    if let Err(error) = validate::validate_checksum(&msg) {
        state_machine.handle(&Event::SessionErrorReceived {
            error,
            poss_dup: None,
        });
        return Ok(());
    }

    // HANDLE

    let msg_seq_num = cb.msg_seq_num;
    // Only session-level types are interpreted here; anything else is an application
    // message for the app channel. Validation has already confirmed the type is on the
    // accepted list, so this arm only sees known application types.
    match cb.msg_type.session_type() {
        Some(LOGON) => {
            let mut heartbt_secs = settings.heartbeat_timeout.as_secs() as u32;
            if let Some(i) = cb.heart_bt_int {
                heartbt_secs = i;
                let heartbt_dur = tokio::time::Duration::from_secs(i as u64);
                fix_timeouts.set_durations(
                    heartbt_dur,
                    test_request_duration(&heartbt_dur),
                    logout_duration(&heartbt_dur),
                );
            }
            state_machine.handle(&Event::LogonReceived(
                msg_seq_num,
                heartbt_secs,
                cb.encrypt_method,
                cb.reset_seq_num_flag.map(|f| f == 'Y').unwrap_or(false),
                to_poss_dup_flag(cb.poss_dup_flag),
            ));
        }
        Some(LOGOUT) => {
            state_machine.handle(&Event::LogoutReceived(
                msg_seq_num,
                to_poss_dup_flag(cb.poss_dup_flag),
            ));
        }
        Some(HEARTBEAT) => {
            state_machine.handle(&Event::HeartbeatReceived(
                msg_seq_num,
                to_poss_dup_flag(cb.poss_dup_flag),
            ));
        }
        Some(SEQUENCE_RESET) => {
            if let Some(nsn) = cb.new_seq_no {
                let maybe_gap_fill = cb
                    .gap_fill
                    .map(GapFillFlag::try_from)
                    .transpose()
                    .map_err(anyhow::Error::msg)?;
                state_machine.handle(&Event::SequenceResetReceived {
                    msg_seq_num,
                    gap_fill: maybe_gap_fill,
                    new_seq_no: nsn,
                    poss_dup: to_poss_dup_flag(cb.poss_dup_flag),
                })
            }
        }
        Some(REJECT) => state_machine.handle(&Event::RejectReceived(
            msg_seq_num,
            to_poss_dup_flag(cb.poss_dup_flag),
        )),
        Some(TEST_REQUEST) => {
            if let Some(test_req_id) = cb.test_req_id {
                state_machine.handle(&Event::TestRequestReceived {
                    msg_seq_num,
                    test_req_id: test_req_id.to_owned(),
                    poss_dup: to_poss_dup_flag(cb.poss_dup_flag),
                })
            }
        }
        Some(RESEND_REQUEST) => {
            let e = match cb.end_seq_no {
                Some(n) if n > 0 => n,
                _ => state_machine.sequences.peek_outgoing() - 1,
            };
            let b = cb.begin_seq_no.unwrap_or(e);

            if session::should_resend(state_machine) {
                let prev_messages = store
                    .get_prev_messages(
                        Arc::clone(&settings.epoch),
                        b,
                        e,
                        state_machine.sequences.peek_outgoing() - 1,
                    )
                    .await?;
                resend_messages(prev_messages, stream, additional_headers, settings, logger)
                    .await?;
            }
            state_machine.handle(&Event::ResendRequestReceived(
                cb.msg_seq_num,
                b,
                e,
                to_poss_dup_flag(cb.poss_dup_flag),
            ));
        }
        // session_type() names only the seven session types matched above.
        _ => {
            if session::should_pass_app_message(state_machine, msg_seq_num) {
                let _ = message_received_event_sender.send(Arc::clone(&msg));
            }
            state_machine.handle(&Event::ApplicationMessageReceived(
                msg_seq_num,
                to_poss_dup_flag(cb.poss_dup_flag),
            ));
        }
    }

    store
        .set_sequences(
            Arc::clone(&settings.epoch),
            state_machine.sequences.peek_outgoing(),
            state_machine.sequences.peek_incoming(),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

async fn disconnect<L>(
    mut request_receiver: mpsc::UnboundedReceiver<Request>,
    store: Store,
    epoch: Arc<String>,
    state_machine: &MyStateMachine,
    stream: TcpStream,
    logger: L,
) -> Result<()>
where
    L: Logger + Send + Sync,
{
    request_receiver.close();
    store.set_sequences(
        epoch,
        state_machine.sequences.peek_outgoing(),
        state_machine.sequences.peek_incoming(),
    )?;
    store.disconnect().await?;
    logger.disconnect().await?;
    stream::disconnect(stream).await;
    Ok(())
}

async fn receive_logon_request(
    request_receiver: &mut mpsc::UnboundedReceiver<Request>,
) -> Option<oneshot::Sender<bool>> {
    loop {
        match request_receiver.recv().await {
            Some(Request::Logon { resp_sender }) => {
                return Some(resp_sender);
            }
            Some(Request::SendMessage { resp_sender, .. }) => {
                let _ = resp_sender.send(false);
            }
            Some(Request::Logout { resp_sender, .. }) => {
                let _ = resp_sender.send(true);
            }
            Some(Request::SetSequenceNumbers { resp_sender, .. }) => {
                let _ = resp_sender.send(false); // Can't set sequence numbers before logon
            }
            None => {
                return None;
            }
        }
    }
}

async fn send_outgoing_messages<L>(
    state_machine: &mut MyStateMachine,
    stream: &mut TcpStream,
    additional_headers: &AdditionalHeaders,
    settings: &SessionSettings,
    store: &Store,
    epoch: Arc<String>,
    logger: &L,
    fix_timeouts: &mut FixTimeouts,
) -> Result<(), SessionError>
where
    L: Logger + Send + Sync,
{
    if !state_machine.outbox.is_empty() {
        fix_timeouts.reset_heartbeat();
    }
    while let Some((msg, maybe_resp_sender)) = state_machine.outbox_pop() {
        let is_logout = msg.msg_type() == "5";

        let msg_seq_num = state_machine.sequences.next_outgoing();
        let msg_buf =
            build_message_with_headers(msg, msg_seq_num, additional_headers, settings).await?;
        stream::send_message(&msg_buf, stream, logger).await?;

        store
            .set_sequences(
                Arc::clone(&epoch),
                state_machine.sequences.peek_outgoing(),
                state_machine.sequences.peek_incoming(),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        store
            .store_outgoing(
                epoch.clone(),
                msg_seq_num,
                Instant::now(),
                Arc::new(msg_buf),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if is_logout {
            state_machine.outbox_clear();
            state_machine.set_logout_resp_sender(maybe_resp_sender);
            state_machine.handle(&Event::LogoutSent);
            fix_timeouts.start_logout_timeout();
            break;
        } else if let Some(resp_sender) = maybe_resp_sender {
            let _ = resp_sender.send(true);
        }
    }
    Ok(())
}

async fn resend_messages<L>(
    mut messages: Vec<(u32, Vec<u8>)>,
    stream: &mut TcpStream,
    additional_headers: &AdditionalHeaders,
    settings: &SessionSettings,
    logger: &L,
) -> Result<(), SessionError>
where
    L: Logger + Send + Sync,
{
    messages.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut session_msg_count = 0;
    for (_, (msg_seq_num, msg)) in messages.iter().enumerate() {
        let transformer = Transformer::try_from(msg.clone())?;
        if transformer.msg_type.is_session() {
            session_msg_count += 1;
            continue;
        }
        if session_msg_count > 0 {
            let msg_buf = build_gap_fill_msg(
                msg_seq_num - session_msg_count,
                *msg_seq_num,
                additional_headers,
                settings,
            )
            .await?;
            stream::send_message(&msg_buf, stream, logger).await?;
            session_msg_count = 0;
        }
        let msg_buf = transform_message(transformer).await?;
        stream::send_message(&msg_buf, stream, logger).await?;
    }
    if session_msg_count > 0 {
        let last_seq_num = messages[messages.len() - 1].0;
        let msg_buf = build_gap_fill_msg(
            last_seq_num - session_msg_count + 1,
            last_seq_num + 1,
            additional_headers,
            settings,
        )
        .await?;
        stream::send_message(&msg_buf, stream, logger).await?;
    }
    Ok(())
}

async fn build_message_with_headers(
    msg: MessageBuilder,
    msg_seq_num: u32,
    additional_headers: &AdditionalHeaders,
    settings: &SessionSettings,
) -> Result<MsgBuf, SessionError> {
    let mut buf = Vec::new();
    let mut cur = tokio::io::BufWriter::new(&mut buf);
    let sending_time = Utc::now();
    let msg = customize_initiator_logon(msg, msg_seq_num, sending_time, settings)?;

    msg.build_async(&mut cur, msg_seq_num, additional_headers, sending_time)
        .await?;
    cur.flush().await?;
    Ok(buf.into())
}

fn customize_initiator_logon(
    mut msg: MessageBuilder,
    msg_seq_num: u32,
    sending_time: DateTime<Utc>,
    settings: &SessionSettings,
) -> Result<MessageBuilder, SessionError> {
    if !matches!(settings.engine_type, FixEngineType::Client) || msg.msg_type() != "A" {
        return Ok(msg);
    }

    let Some(hook) = settings.initiator_logon_hook.as_ref() else {
        return Ok(msg);
    };

    let ctx = InitiatorLogonContext {
        begin_string: &settings.begin_string,
        sender_comp_id: &settings.sender_comp_id,
        target_comp_id: &settings.target_comp_id,
        target_sub_id: settings.target_sub_id.as_deref(),
        msg_seq_num,
        sending_time,
        heart_bt_int_secs: settings.heartbeat_timeout.as_secs() as u32,
    };

    hook.customize(&ctx, &mut msg)
        .map_err(|err| SessionError::LogonCustomize(err.to_string()))?;
    Ok(msg)
}

async fn build_gap_fill_msg(
    msg_seq_num: u32,
    new_seq_num: u32,
    additional_headers: &AdditionalHeaders,
    settings: &SessionSettings,
) -> Result<MsgBuf, SessionError> {
    let builder = MessageBuilder::new(&settings.begin_string, MsgType::SEQUENCE_RESET.into())
        .push(Tags::NewSeqNo, SerializedInt::from(new_seq_num).as_bytes())
        .push(Tags::GapFillFlag, b"Y");
    let msg =
        build_message_with_headers(builder, msg_seq_num, additional_headers, settings).await?;
    let transformer = Transformer::try_from(msg.0)?;
    transform_message(transformer).await
}

async fn transform_message(transformer: Transformer) -> Result<MsgBuf, SessionError> {
    let mut buf = Vec::new();
    let mut cur = tokio::io::BufWriter::new(&mut buf);
    transformer
        .build_async(&mut cur)
        .await
        .or(Err(SessionError::ResendError))?;
    cur.flush().await?;
    Ok(buf.into())
}

fn to_poss_dup_flag(maybe_flag: Option<char>) -> Option<PossDupFlag> {
    maybe_flag.map(|f| PossDupFlag::try_from(f).unwrap_or(PossDupFlag::NO))
}

async fn is_new_session(store: &Store, settings: &SessionSettings) -> Result<bool> {
    if matches!(settings.engine_type, FixEngineType::Server) {
        return Ok(false);
    }
    let last_send_time = store.last_send_time(settings.epoch.clone()).await?;
    let session_start = match settings.session_start_instant {
        Some(instant) => instant,
        None => NaiveDateTime::new(Utc::now().date_naive(), settings.start_time).and_utc(),
    };
    Ok(last_send_time < Some(session_start))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fix::decode::ParsedPeek;
    use crate::fix::encode::AdditionalHeaders;
    use crate::fix::generated::Tags;
    use crate::InitiatorLogonHook;
    use anyhow::Result as AnyhowResult;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, BufReader};

    struct EchoLogonHook;

    impl InitiatorLogonHook for EchoLogonHook {
        fn customize(
            &self,
            ctx: &crate::InitiatorLogonContext<'_>,
            builder: &mut MessageBuilder,
        ) -> AnyhowResult<()> {
            let payload = format!(
                "{}|{}|{}|{}|{}",
                ctx.msg_seq_num,
                ctx.sending_time.format(crate::fix::encode::TIME_FORMAT),
                ctx.sender_comp_id,
                ctx.target_comp_id,
                ctx.heart_bt_int_secs
            );
            builder.push_mut(1137u32, b"9");
            builder.push_mut(
                Tags::RawDataLength,
                SerializedInt::from(payload.len() as u32).as_bytes(),
            );
            builder.push_mut(Tags::RawData, payload.as_bytes());
            Ok(())
        }
    }
    #[tokio::test]
    async fn my_test() {
        let message_bytes = vec![
        &b"8=FIX.4.2\x019=77\x0135=A\x0134=1\x0149=GSLLDMAUAT\x0152=20220920-17:01:58.896\x0156=AMLRLLDMAUAT\x0198=0\x01108=30\x0110=126\x01"[..],
        &b"8=FIX.4.2\x019=77\x0135=A\x0134=2\x0149=AMLRLLDMAUAT\x0152=20220920-17:11:00.860\x0156=GSLLDMAUAT\x0198=0\x01108=30\x0110=106\x01"[..],
        &b"8=FIX.4.2\x019=0287\x0135=8\x0134=15\x0149=GSLLDMAUAT\x0152=20220920-17:24:23.974\x0156=AMLRLLDMAUAT\x011=\x016=0.000000\x0111=the-01GDDYVW95KB9XTD2GA7EC4CY2\x0114=0\x0117=BzdLZDozKgI=\x0120=0\x0122=J\x0137=BzdLZDkzKgI=\x0138=2\x0139=8\x0140=2\x0144=0.890000\x0148=RBLX  220930P00034000\x0154=1\x0158=GS:InvalidAccount\x0159=3\x0160=20220920-17:24:23.974\x01103=0\x01150=8\x01151=0\x0110=008\x01"[..],
        ];
        for data in message_bytes.iter() {
            let mut r = BufReader::new(*data);
            let ParsedPeek {
                len_start,
                body_length,
                len_end,
                ..
            } = crate::fix::decode::parse_peeked_prefix(&data[..32]).unwrap();
            assert_eq!(len_start, 12);
            // assert_eq!(len_end, 15);
            let mut msg_buf = vec![0; 32 + (body_length - (32 - (len_end + 1)) + 7)];
            r.read_exact(&mut msg_buf[..])
                .await
                .expect("expected no error");
            assert_eq!(&data[..], msg_buf);
        }
    }

    #[test]
    fn test_validate_msg_length() {
        let correct = &b"8=FIX.4.2\x019=21\x0134=0\x0149=send\x0156=rec\x0110=000\x01"[..];
        let short = &b"8=FIX.4.2\x019=14\x0134=0\x0149=send\x0156=rec\x01"[..];
        let long = &b"8=FIX.4.2\x019=23\x0134=0\x0149=send\x0156=rec\x0110=000\x018="[..];

        assert_eq!(
            validate::validate_msg_length(correct, correct.len()).is_ok(),
            true
        );
        assert_eq!(
            validate::validate_msg_length(short, short.len()).is_err(),
            true
        );
        assert_eq!(
            validate::validate_msg_length(long, long.len()).is_err(),
            true
        );
    }

    #[test]
    fn test_parser_callback() {
        let mut cb: SessionParserCallback = Default::default();
        assert_eq!(
            crate::fix::decode::parse(
                &b"8=FIX.4.2\x019=21\x0195=10\x0196=123\x01456789\x0110=000\x01"[..],
                &mut cb
            )
            .is_err(),
            false
        );
        let mut cb: SessionParserCallback = Default::default();
        assert_eq!(
            crate::fix::decode::parse(
                &b"8=FIX.4.2\x019=21\x0195=1a\x0196=123\x01456789\x0110=000\x01"[..],
                &mut cb
            )
            .is_err(),
            true
        );
        let mut cb: SessionParserCallback = Default::default();
        assert_eq!(
            crate::fix::decode::parse(
                &b"8=FIX.4.2\x019=21\x0195=10\x0196=123\x0145678910\x0110=000\x01"[..],
                &mut cb
            )
            .is_err(),
            false
        );
        let mut cb: SessionParserCallback = Default::default();
        assert_eq!(
            crate::fix::decode::parse(
                &b"8=FIX.4.2\x019=21\x0195=10\x0134=1\x0196=123\x01456789\x0110=000\x01"[..],
                &mut cb
            )
            .is_err(),
            false
        );
    }

    #[tokio::test]
    async fn initiator_logon_hook_can_use_final_header_context() {
        let settings = SessionSettings::builder()
            .with_sender_comp_id("sender")
            .with_target_comp_id("target")
            .with_socket_addr("127.0.0.1:9000".parse::<SocketAddr>().expect("socket addr"))
            .with_store_path(PathBuf::from("/tmp/forgefix-test-store.db"))
            .with_log_dir(PathBuf::from("/tmp/forgefix-test-logs"))
            .with_begin_string("FIXT.1.1")
            .with_heartbeat_timeout(Duration::from_secs(30))
            .with_initiator_logon_hook(Arc::new(EchoLogonHook))
            .build()
            .expect("settings build");
        let additional_headers = AdditionalHeaders::build(&settings);
        let msg_buf = build_message_with_headers(
            crate::fix::session::build_logon_message("FIXT.1.1", 30),
            7,
            &additional_headers,
            &settings,
        )
        .await
        .expect("message build");
        let encoded = String::from_utf8(msg_buf.0).expect("utf8 message");

        assert!(encoded.contains("35=A\x01"));
        assert!(encoded.contains("34=7\x01"));
        assert!(encoded.contains("49=sender\x01"));
        assert!(encoded.contains("56=target\x01"));
        assert!(encoded.contains("1137=9\x01"));
        let raw_data = encoded
            .split('\x01')
            .find_map(|field| field.strip_prefix("96="))
            .expect("raw data field");
        let raw_data_len = encoded
            .split('\x01')
            .find_map(|field| field.strip_prefix("95="))
            .expect("raw data length field")
            .parse::<usize>()
            .expect("raw data length is numeric");
        assert_eq!(raw_data_len, raw_data.len());
        assert!(raw_data.starts_with("7|"));
        assert!(raw_data.contains("|sender|target|30"));
    }

    struct NoopLogger;

    impl Logger for NoopLogger {
        fn log_message(&self, _msg: &MsgBuf) -> Result<(), SessionError> {
            Ok(())
        }
    }

    /// An inbound message from the counterparty ("target") to us ("sender"), with a valid
    /// BodyLength, current SendingTime and CheckSum.
    fn inbound_msg(msg_type: &str, msg_seq_num: u32, body: &str) -> MsgBuf {
        let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f");
        let rest = format!(
            "35={msg_type}\x0134={msg_seq_num}\x0149=target\x0152={sending_time}\x0156=sender\x01{body}"
        );
        let mut msg = format!("8=FIXT.1.1\x019={}\x01{rest}", rest.len()).into_bytes();
        let checksum = msg.iter().map(|b| *b as u32).sum::<u32>() % 256;
        msg.extend_from_slice(format!("10={checksum:03}\x01").as_bytes());
        msg.into()
    }

    /// PossDupFlag and OrigSendingTime fields that mark a body as a resent copy.
    fn poss_dup_fields() -> String {
        let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f");
        format!("43=Y\x01122={sending_time}\x01")
    }

    /// What a session did with a run of inbound messages.
    struct InboundRun {
        /// MsgType of every message handed to the app channel, in order.
        delivered: Vec<String>,
        /// Every message we wrote to the counterparty, in order, with SOH shown as `|`.
        sent: Vec<String>,
        /// The next expected inbound seq afterwards.
        next_incoming: u32,
        /// Whether the session ended in the Error state.
        errored: bool,
    }

    impl InboundRun {
        /// The messages of MsgType `msg_type` we wrote to the counterparty.
        fn sent_of_type(&self, msg_type: &str) -> Vec<&str> {
            let field = format!("|35={msg_type}|");
            self.sent
                .iter()
                .filter(|msg| msg.contains(&field))
                .map(String::as_str)
                .collect()
        }
    }

    /// Splits bytes written to the counterparty into messages, SOH shown as `|`.
    fn split_sent(wire: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(wire).replace('\x01', "|");
        let mut messages = Vec::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("|10=") {
            let end = at + "|10=000|".len();
            messages.push(rest[..end].to_owned());
            rest = &rest[end..];
        }
        messages
    }

    /// Runs `msgs` through `handle_msg` on a fresh initiator session that has sent its Logon,
    /// expects inbound seq `next_incoming`, and accepts the extra MsgTypes `accepted`.
    /// Flushes the session's outbox to the counterparty after each message, as the session
    /// loop does, and reports what reached the app and what went out on the wire.
    async fn run_inbound(next_incoming: u32, accepted: &[&str], msgs: Vec<MsgBuf>) -> InboundRun {
        // Unique per call: tests run in parallel and must not share a store file.
        static STORE_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let store_path = std::env::temp_dir().join(format!(
            "forgefix-inbound-{}-{}.db",
            std::process::id(),
            STORE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&store_path);
        let settings = SessionSettings::builder()
            .with_sender_comp_id("sender")
            .with_target_comp_id("target")
            .with_socket_addr("127.0.0.1:9000".parse::<SocketAddr>().expect("socket addr"))
            .with_store_path(store_path.clone())
            .with_log_dir(PathBuf::from("/tmp/forgefix-test-logs"))
            .with_begin_string("FIXT.1.1")
            .with_accepted_msg_types(accepted)
            .build()
            .expect("settings build");
        let additional_headers = AdditionalHeaders::build(&settings);
        let store = Store::build(&settings).expect("store");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let mut stream = TcpStream::connect(listener.local_addr().expect("addr"))
            .await
            .expect("connect");
        let (mut counterparty, _) = listener.accept().await.expect("accept");
        let heartbeat = Duration::from_secs(30);
        let mut fix_timeouts = FixTimeouts::new(heartbeat, heartbeat, heartbeat);
        let (app_tx, mut app_rx) = mpsc::unbounded_channel();
        let mut state_machine = MyStateMachine::new(&settings, (next_incoming, 1));
        state_machine.handle(&Event::Connect(false));

        for msg in std::iter::once(None).chain(msgs.into_iter().map(Some)) {
            if let Some(msg) = msg {
                handle_msg(
                    Ok(msg),
                    &mut state_machine,
                    &mut fix_timeouts,
                    &store,
                    &settings,
                    &mut stream,
                    &NoopLogger,
                    &additional_headers,
                    &app_tx,
                )
                .await
                .expect("handle_msg");
            }
            send_outgoing_messages(
                &mut state_machine,
                &mut stream,
                &additional_headers,
                &settings,
                &store,
                Arc::clone(&settings.epoch),
                &NoopLogger,
                &mut fix_timeouts,
            )
            .await
            .expect("send_outgoing_messages");
        }
        drop(stream);
        let mut wire = Vec::new();
        counterparty
            .read_to_end(&mut wire)
            .await
            .expect("read sent messages");

        let delivered = std::iter::from_fn(|| app_rx.try_recv().ok())
            .map(|msg| {
                let text = String::from_utf8_lossy(&msg.0).into_owned();
                text.split('\x01')
                    .find_map(|field| field.strip_prefix("35="))
                    .expect("MsgType")
                    .to_owned()
            })
            .collect();
        let _ = std::fs::remove_file(&store_path);
        InboundRun {
            delivered,
            sent: split_sent(&wire),
            next_incoming: state_machine.sequences.peek_incoming(),
            errored: session::in_error_state(&state_machine),
        }
    }

    /// A venue-proprietary multi-character type (`35=UMS`) must reach the app like any
    /// application message and advance the expected inbound seq. Before multi-character MsgType support it was dropped
    /// as garbled without advancing, so every later message (fills included) was lost.
    #[tokio::test]
    async fn multi_character_msg_type_is_delivered_and_advances_inbound_seq() {
        let InboundRun {
            delivered,
            next_incoming,
            ..
        } = run_inbound(
            1,
            &["UMS"],
            vec![
                inbound_msg("A", 1, "98=0\x01108=30\x01"),
                inbound_msg("UMS", 2, "55=TEST\x01"),
                inbound_msg("8", 3, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(delivered, ["UMS", "8"]);
        assert_eq!(next_incoming, 4);
    }

    /// Resend recovery with a multi-character type in the replayed range: the session
    /// expects seq 5, the counterparty logs on at 20 (a gap), we request a resend, and it
    /// replays the multi-character message as PossDup and gap-fills the rest. The session
    /// must accept both and catch up without a manual sequence reset.
    #[tokio::test]
    async fn recovers_from_stalled_multi_character_msg_type_via_resend() {
        let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f");
        let poss_dup = format!("43=Y\x01122={sending_time}\x01");
        let InboundRun {
            delivered,
            next_incoming,
            ..
        } = run_inbound(
            5,
            &["UMS"],
            vec![
                inbound_msg("A", 20, "98=0\x01108=30\x01"),
                inbound_msg("UMS", 5, &format!("{poss_dup}55=TEST\x01")),
                inbound_msg("4", 6, &format!("{poss_dup}123=Y\x0136=21\x01")),
                inbound_msg("8", 21, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(delivered, ["UMS", "8"]);
        assert_eq!(next_incoming, 22);
    }

    /// A type off the accepted list is rejected at validation — but the rejection still
    /// advances the inbound seq, so the session keeps flowing (no stall) and later
    /// messages are delivered normally.
    #[tokio::test]
    async fn off_list_msg_type_is_rejected_but_session_keeps_flowing() {
        let InboundRun {
            delivered,
            next_incoming,
            ..
        } = run_inbound(
            1,
            &[],
            vec![
                inbound_msg("A", 1, "98=0\x01108=30\x01"),
                inbound_msg("z", 2, "58=custom\x01"),
                inbound_msg("8", 3, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(delivered, ["8"]);
        assert_eq!(next_incoming, 4);
    }

    /// A multi-character type the session was not configured to accept is rejected like
    /// any off-list type: the session keeps flowing and later messages are delivered.
    #[tokio::test]
    async fn unconfigured_multi_character_msg_type_is_rejected_but_session_keeps_flowing() {
        let run = run_inbound(
            1,
            &[],
            vec![
                inbound_msg("A", 1, "98=0\x01108=30\x01"),
                inbound_msg("UMS", 2, "55=TEST\x01"),
                inbound_msg("8", 3, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(run.delivered, ["8"]);
        assert_eq!(run.next_incoming, 4);
        let rejects = run.sent_of_type("3");
        assert_eq!(
            rejects.len(),
            1,
            "one Reject expected, sent: {:#?}",
            run.sent
        );
        assert!(
            rejects[0].contains("|45=2|"),
            "Reject must reference seq 2: {}",
            rejects[0]
        );
        assert!(
            rejects[0].contains("|372=UMS|"),
            "Reject must reference UMS: {}",
            rejects[0]
        );
    }

    /// Resend recovery where the replayed message is NOT accepted: it must be answered
    /// with a Reject and consumed, so the gap fill that follows completes the range and the
    /// session catches up. Before, the rejected message never advanced the resend range,
    /// every later replay was skipped as out of order, and the session stalled.
    #[tokio::test]
    async fn rejected_message_in_resend_range_is_consumed_and_session_recovers() {
        let sending_time = Utc::now().format("%Y%m%d-%H:%M:%S%.3f");
        let poss_dup = format!("43=Y\x01122={sending_time}\x01");
        let InboundRun {
            delivered,
            next_incoming,
            ..
        } = run_inbound(
            5,
            &[],
            vec![
                inbound_msg("A", 20, "98=0\x01108=30\x01"),
                inbound_msg("UMS", 5, &format!("{poss_dup}55=TEST\x01")),
                inbound_msg("4", 6, &format!("{poss_dup}123=Y\x0136=21\x01")),
                inbound_msg("8", 21, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(delivered, ["8"]);
        assert_eq!(next_incoming, 22);
    }

    /// A stale PossDup copy of a message we already received is ignored even when its type
    /// would be rejected: like any other duplicate it must not move the expected inbound
    /// seq. Counting it made the next genuine message look too low and logged us out.
    #[tokio::test]
    async fn rejected_stale_poss_dup_does_not_advance_inbound_seq() {
        let run = run_inbound(
            10,
            &[],
            vec![
                inbound_msg("A", 10, "98=0\x01108=30\x01"),
                inbound_msg("AE", 5, &format!("{}55=TEST\x01", poss_dup_fields())),
                inbound_msg("8", 11, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        assert_eq!(run.delivered, ["8"]);
        assert_eq!(run.next_incoming, 12);
        assert!(
            run.sent_of_type("5").is_empty(),
            "no Logout expected, sent: {:#?}",
            run.sent
        );
        assert!(!run.errored);
    }

    /// A message that would be rejected but arrives past a sequence gap must trigger a
    /// ResendRequest for the gap like any other message. It is then rejected once, when its
    /// replay arrives in order. Counting it on arrival instead skipped the gap: 11 was never
    /// requested again, so whatever it carried was lost.
    #[tokio::test]
    async fn rejected_message_past_a_gap_requests_resend_of_the_gap() {
        let run = run_inbound(
            10,
            &[],
            vec![
                inbound_msg("A", 10, "98=0\x01108=30\x01"),
                inbound_msg("AE", 15, "55=TEST\x01"),
                inbound_msg("4", 11, &format!("{}123=Y\x0136=15\x01", poss_dup_fields())),
                inbound_msg("AE", 15, &format!("{}55=TEST\x01", poss_dup_fields())),
                inbound_msg("8", 16, "11=order-1\x0139=2\x01150=F\x01"),
            ],
        )
        .await;
        let resend_requests = run.sent_of_type("2");
        assert_eq!(
            resend_requests.len(),
            1,
            "one ResendRequest expected, sent: {:#?}",
            run.sent
        );
        assert!(
            resend_requests[0].contains("|7=11|"),
            "ResendRequest must start at the gap (11): {}",
            resend_requests[0]
        );
        let rejects = run.sent_of_type("3");
        assert_eq!(
            rejects.len(),
            1,
            "one Reject expected, sent: {:#?}",
            run.sent
        );
        assert!(
            rejects[0].contains("|45=15|"),
            "Reject must reference seq 15: {}",
            rejects[0]
        );
        assert_eq!(run.delivered, ["8"]);
        assert_eq!(run.next_incoming, 17);
    }

    #[test]
    fn invalid_accepted_msg_type_fails_at_build() {
        for bad in ["", "ABCDE", "U S", "U\u{1}S"] {
            let result = SessionSettings::builder()
                .with_sender_comp_id("sender")
                .with_target_comp_id("target")
                .with_socket_addr("127.0.0.1:9000".parse::<SocketAddr>().expect("socket addr"))
                .with_store_path(PathBuf::from("/tmp/forgefix-test-store.db"))
                .with_log_dir(PathBuf::from("/tmp/forgefix-test-logs"))
                .with_accepted_msg_types([bad])
                .build();
            assert!(matches!(
                result,
                Err(crate::ApplicationError::InvalidSetting(_))
            ));
        }
    }

    #[tokio::test]
    async fn gap_fill_uses_session_begin_string() {
        let settings = SessionSettings::builder()
            .with_sender_comp_id("sender")
            .with_target_comp_id("target")
            .with_socket_addr("127.0.0.1:9000".parse::<SocketAddr>().expect("socket addr"))
            .with_store_path(PathBuf::from("/tmp/forgefix-test-store.db"))
            .with_log_dir(PathBuf::from("/tmp/forgefix-test-logs"))
            .with_begin_string("FIXT.1.1")
            .build()
            .expect("settings build");
        let additional_headers = AdditionalHeaders::build(&settings);
        let msg_buf = build_gap_fill_msg(2, 85, &additional_headers, &settings)
            .await
            .expect("gap fill build");
        let encoded = String::from_utf8(msg_buf.0).expect("utf8 message");

        assert!(encoded.starts_with("8=FIXT.1.1\x01"));
        assert!(encoded.contains("35=4\x01"));
        assert!(encoded.contains("123=Y\x01"));
        assert!(encoded.contains("36=85\x01"));
    }
}
