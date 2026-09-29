//! A peer's session-level `Reject<3>` is correlated to the rejected message by `RefSeqNum(45)`.
//! These tests run an initiator against an acceptor over localhost TCP.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use forgefix::fix::encode::{MessageBuilder, SerializedInt};
use forgefix::fix::generated::{MsgType, Tags};
use forgefix::fix::mem::MsgBuf;
use forgefix::{
    FixApplicationAcceptor, FixApplicationHandle, FixApplicationInitiator, SessionSettings,
    SessionSettingsBuilder,
};
use tempfile::TempDir;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

struct Peer {
    handle: FixApplicationHandle,
    app_rx: UnboundedReceiver<Arc<MsgBuf>>,
    _dir: TempDir,
}

fn settings(sender: &str, target: &str, addr: SocketAddr, dir: &TempDir) -> SessionSettingsBuilder {
    SessionSettings::builder()
        .with_sender_comp_id(sender)
        .with_target_comp_id(target)
        .with_socket_addr(addr)
        .with_store_path(dir.path().join("store.db"))
        .with_log_dir(dir.path().to_path_buf())
}

/// Log an initiator (`INIT`) on to an acceptor (`ACC`), returning `(initiator, acceptor)`.
async fn connect(forward_session_rejects: bool) -> (Peer, Peer) {
    let addr = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("free port");
    let acceptor_dir = TempDir::new().expect("tempdir");
    let initiator_dir = TempDir::new().expect("tempdir");

    let acceptor_settings = settings("ACC", "INIT", addr, &acceptor_dir)
        .build()
        .expect("settings");
    let mut acceptor = FixApplicationAcceptor::build(acceptor_settings).expect("acceptor");
    let accepted = tokio::spawn(async move { acceptor.accept().await.expect("accept") });

    let initiator_settings = settings("INIT", "ACC", addr, &initiator_dir)
        .with_forward_session_rejects(forward_session_rejects)
        .build()
        .expect("settings");
    let (initiator_handle, initiator_rx) = FixApplicationInitiator::build(initiator_settings)
        .expect("initiator")
        .initiate()
        .await
        .expect("initiate");
    let (acceptor_handle, acceptor_rx) = accepted.await.expect("accept task");

    let (initiator_logon, acceptor_logon) = tokio::join!(
        initiator_handle.start_async(),
        acceptor_handle.start_async()
    );
    initiator_logon.expect("initiator logon");
    acceptor_logon.expect("acceptor logon");

    (
        Peer {
            handle: initiator_handle,
            app_rx: initiator_rx,
            _dir: initiator_dir,
        },
        Peer {
            handle: acceptor_handle,
            app_rx: acceptor_rx,
            _dir: acceptor_dir,
        },
    )
}

fn field(msg: &MsgBuf, tag: u32) -> Option<&str> {
    let prefix = format!("{tag}=");
    std::str::from_utf8(&msg.0)
        .ok()?
        .split('\x01')
        .find_map(|field| field.strip_prefix(prefix.as_str()))
}

async fn recv(peer: &mut Peer) -> Arc<MsgBuf> {
    timeout(RECV_TIMEOUT, peer.app_rx.recv())
        .await
        .expect("message within timeout")
        .expect("channel open")
}

/// Send a `QuoteRequest<R>` from the initiator, and have the acceptor reject it with a
/// `Reject<3>` referencing the `MsgSeqNum(34)` it arrived with.
async fn send_request_and_reject(initiator: &Peer, acceptor: &mut Peer) -> u32 {
    let request = MessageBuilder::new(
        &initiator.handle.begin_string(),
        MsgType::QUOTE_REQUEST.into(),
    )
    .push(Tags::QuoteReqID, b"LOCATE-1");
    let seq_num = initiator
        .handle
        .send_message_with_seq_num_async(request)
        .await
        .expect("request sent");

    let received = recv(acceptor).await;
    assert_eq!(field(&received, 35), Some("R"));
    assert_eq!(field(&received, 34), Some(seq_num.to_string().as_str()));

    let reject = MessageBuilder::new(&acceptor.handle.begin_string(), MsgType::REJECT.into())
        .push(Tags::RefSeqNum, SerializedInt::from(seq_num).as_bytes())
        .push(Tags::RefMsgType, b"R")
        .push(Tags::Text, b"invalid request");
    acceptor
        .handle
        .send_message_async(reject)
        .await
        .expect("reject sent");
    seq_num
}

#[tokio::test]
async fn forwarded_session_reject_references_the_returned_seq_num() {
    let (mut initiator, mut acceptor) = connect(true).await;

    let seq_num = send_request_and_reject(&initiator, &mut acceptor).await;

    let reject = recv(&mut initiator).await;
    assert_eq!(field(&reject, 35), Some("3"));
    assert_eq!(field(&reject, 45), Some(seq_num.to_string().as_str()));
    assert_eq!(field(&reject, 372), Some("R"));
}

#[tokio::test]
async fn session_rejects_are_not_forwarded_by_default() {
    let (mut initiator, mut acceptor) = connect(false).await;

    send_request_and_reject(&initiator, &mut acceptor).await;
    let report = MessageBuilder::new(
        &acceptor.handle.begin_string(),
        MsgType::EXECUTION_REPORT.into(),
    )
    .push(Tags::ClOrdID, b"AFTER-REJECT");
    acceptor
        .handle
        .send_message_async(report)
        .await
        .expect("report sent");

    // The reject was sent first, so the report arriving first shows the reject was withheld.
    let next = recv(&mut initiator).await;
    assert_eq!(field(&next, 35), Some("8"));
    assert_eq!(field(&next, 11), Some("AFTER-REJECT"));
}
