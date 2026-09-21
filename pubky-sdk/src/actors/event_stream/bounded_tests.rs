use super::EventStreamBuilder;
use crate::errors::Result;
use futures_util::{FutureExt, StreamExt, TryStreamExt, stream};
use sse_core::MessageEvent;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

async fn collect(chunks: Vec<Vec<u8>>, limit: usize) -> Result<Vec<MessageEvent>> {
    EventStreamBuilder::sse_stream(stream::iter(chunks.into_iter().map(Ok::<_, &str>)), limit)
        .try_collect()
        .await
}

struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn stream_parses_whole_and_fragmented_sse_messages() {
    let body = b"\xef\xbb\xbf: keepalive\r\nretry: 10\r\nevent: PUT\r\n\
                 data: caf\xc3\xa9\r\ndata: \xff\r\n\r\ndata: next\n\n";
    let expected = vec![
        MessageEvent {
            event: "PUT".into(),
            data: "café\n\u{fffd}".into(),
            last_event_id: None,
        },
        MessageEvent {
            event: "message".into(),
            data: "next".into(),
            last_event_id: None,
        },
    ];
    for limit in [32, usize::MAX] {
        for chunks in [vec![body.to_vec()], body.iter().map(|b| vec![*b]).collect()] {
            assert_eq!(collect(chunks, limit).await.unwrap(), expected);
        }
    }
}

#[tokio::test]
async fn exact_limit_accepts_and_next_byte_rejects() {
    for ending in ["\n", "\r\n", "\r"] {
        let field = format!("data: value{ending}");
        let body = format!("{field}{ending}");
        for limit in [5, 6, usize::MAX] {
            assert_eq!(
                collect(vec![body.as_bytes().to_vec()], limit)
                    .await
                    .unwrap()[0]
                    .data,
                "value"
            );
        }
        let error = collect(body.bytes().map(|b| vec![b]).collect(), 4)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("SSE event exceeds the configured limit")
        );
    }
    // Field prefixes, framing and the leading BOM do not consume the payload budget.
    collect(vec![b"\xef\xbb\xbfdata: x\n\n".to_vec()], 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn data_name_and_id_have_separate_limits() {
    for prefix in ["data: ", "event: ", "id: "] {
        let body = format!("{prefix}{}", "x".repeat(33));
        assert!(
            collect(body.bytes().map(|b| vec![b]).collect(), 32)
                .await
                .is_err(),
            "{prefix}"
        );
    }
    for body in ["data: x\n".repeat(20), "data\n".repeat(40)] {
        collect(vec![body.into_bytes()], 32).await.unwrap_err();
    }
    let body = "event: old\nevent: PUT\nid: old\nid: new\ndata: ab\ndata: cd\n\n";
    let events = collect(vec![body.as_bytes().to_vec()], 5).await.unwrap();
    assert_eq!(events[0].event, "PUT");
    assert_eq!(events[0].data, "ab\ncd");
    collect(vec![body.as_bytes().to_vec()], 4)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn comments_unknown_fields_and_retry_do_not_consume_the_payload_budget() {
    for prefix in [":", "unknown: ", "retry: "] {
        let body = format!("{prefix}{}\ndata: x\n\n", "9".repeat(100_000));
        let events = collect(vec![body.into_bytes()], 1).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "x");
    }
}

#[tokio::test]
async fn ready_chunks_yield_to_allow_cancellation() {
    let body = format!(":{}\n\ndata: x\n\n", "x".repeat(128 * 1024)).into_bytes();
    for chunks in [
        vec![body.clone()],
        body.chunks(1024).map(<[u8]>::to_vec).collect(),
    ] {
        let source = stream::iter(chunks.into_iter().map(Ok::<_, &str>));
        let mut decoded = Box::pin(EventStreamBuilder::sse_stream(source, 1));
        assert!(decoded.next().now_or_never().is_none());
        assert_eq!(decoded.next().await.unwrap().unwrap().data, "x");
    }
}

#[tokio::test]
async fn payload_budget_resets_between_events_and_never_limits_the_whole_response() {
    let body = ":keepalive\r\n\r\nevent: unused\n\ndata: x\n\n".repeat(2000);
    let events = collect(vec![body.into_bytes()], 14).await.unwrap();
    assert_eq!(events.len(), 2000);
    assert!(events.iter().all(|e| e.event == "message" && e.data == "x"));
}

#[tokio::test]
async fn overflow_drops_source_before_yielding_without_waiting_for_eof() {
    for chunks in [
        vec![format!("data: {}", "x".repeat(17)).into_bytes()],
        vec![format!("data: {}", "x".repeat(16)).into_bytes(), vec![b'x']],
    ] {
        let dropped = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&polls);
        let source = stream::unfold(
            (chunks.into_iter(), DropFlag(Arc::clone(&dropped))),
            move |(mut chunks, guard)| {
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    match chunks.next() {
                        Some(chunk) => Some((Ok::<_, &str>(chunk), (chunks, guard))),
                        None => std::future::pending().await,
                    }
                }
            },
        );
        let mut decoded = Box::pin(EventStreamBuilder::sse_stream(source, 16));
        let error = tokio::time::timeout(Duration::from_secs(1), decoded.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("16 bytes"));
        assert!(
            dropped.load(Ordering::SeqCst),
            "body must drop while decoder is retained"
        );
        let previous = polls.load(Ordering::SeqCst);
        assert!(decoded.next().await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), previous);
    }
}

#[tokio::test]
async fn transport_error_terminates_and_eof_discards_partial_event() {
    for limit in [32, usize::MAX] {
        let results: Vec<_> = EventStreamBuilder::sse_stream(
            stream::iter([Ok("data: x\n\n"), Err("broken"), Ok("data: never\n\n")]),
            limit,
        )
        .collect()
        .await;
        assert_eq!(results.len(), 2);
        assert!(
            results[1]
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("broken")
        );
        for body in [
            &b"data: x"[..],
            b"data: x\n",
            b"data: x\r",
            b"data: x\r\n",
            b"data: \xe2",
        ] {
            assert!(
                collect(vec![body.to_vec()], limit)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[tokio::test]
async fn cr_terminated_event_does_not_wait_for_another_byte() {
    let source = stream::iter([Ok::<_, &str>("data: x\r\r")]).chain(stream::pending());
    let mut decoded = Box::pin(EventStreamBuilder::sse_stream(source, 32));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), decoded.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .data,
        "x"
    );
}
