use super::*;
use futures_util::TryStreamExt;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

async fn collect(chunks: Vec<Vec<u8>>, limit: usize) -> Result<Vec<Event>> {
    Decoder::decode(stream::iter(chunks.into_iter().map(Ok::<_, &str>)), limit)
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
async fn framing_is_independent_of_chunk_boundaries() {
    for ending in ["\n", "\r\n", "\r"] {
        let body = format!(
            "\u{feff}: hello{ending}event: ignored{ending}event: PUT{ending}data: café 🦀{ending}data:  two{ending}id: ignored{ending}retry: 10{ending}future: yes{ending}{ending}data{ending}{ending}data: unfinished"
        );
        let expected = vec![
            Event {
                event: "PUT".into(),
                data: "café 🦀\n two".into(),
                ..Event::default()
            },
            Event {
                event: "message".into(),
                ..Event::default()
            },
        ];
        for split in 0..=body.len() {
            assert_eq!(
                collect(
                    vec![
                        body.as_bytes()[..split].to_vec(),
                        body.as_bytes()[split..].to_vec()
                    ],
                    4096
                )
                .await
                .unwrap(),
                expected,
                "ending {ending:?}, split {split}"
            );
        }
        assert_eq!(
            collect(body.bytes().map(|b| vec![b]).collect(), 4096)
                .await
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn bom_is_stripped_only_at_the_start_of_the_stream() {
    let body =
        b"\xef\xbb\xbfdata: first\n\n\xef\xbb\xbfdata: ignored\n\ndata: \xef\xbb\xbfvalue\n\n";
    let events = collect(body.iter().map(|b| vec![*b]).collect(), 4096)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].data, "first");
    assert_eq!(events[1].data, "\u{feff}value");
}

#[tokio::test]
async fn exact_limit_accepts_and_next_byte_rejects() {
    for ending in ["\n", "\r\n", "\r"] {
        let field = format!("data: value{ending}");
        let body = format!("{field}{ending}");
        for limit in [field.len(), field.len() + 1, usize::MAX] {
            assert_eq!(
                collect(vec![body.as_bytes().to_vec()], limit)
                    .await
                    .unwrap()[0]
                    .data,
                "value"
            );
        }
        let error = collect(body.bytes().map(|b| vec![b]).collect(), field.len() - 1)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("SSE event exceeds the configured limit")
        );
    }
    // A BOM counts even though it is removed before interpreting the first field.
    collect(vec![b"\xef\xbb\xbfdata: x\n\n".to_vec()], 10)
        .await
        .unwrap_err();
    collect(vec![b"\xef\xbb\xbfdata: x\n\n".to_vec()], 11)
        .await
        .unwrap();
}

#[tokio::test]
async fn every_field_and_comment_counts_toward_the_block_limit() {
    for prefix in [
        "data: pubky://",
        "event: ",
        ":",
        "unknown: ",
        "id: ",
        "retry: ",
        "data: content_hash: ",
    ] {
        let body = format!("{prefix}{}", "x".repeat(33));
        assert!(
            collect(body.bytes().map(|b| vec![b]).collect(), 32)
                .await
                .is_err(),
            "{prefix}"
        );
    }
    for body in [
        "data: x\n".repeat(20),
        ":x\n".repeat(40),
        "unknown: x\n".repeat(20),
    ] {
        collect(vec![body.into_bytes()], 32).await.unwrap_err();
    }
}

#[tokio::test]
async fn budget_resets_at_empty_blocks_and_never_limits_the_whole_response() {
    let body = ":keepalive\r\n\r\nevent: unused\n\ndata: x\n\n".repeat(2000);
    let events = collect(vec![body.into_bytes()], 14).await.unwrap();
    assert_eq!(events.len(), 2000);
    assert!(events.iter().all(|e| e.event == "message" && e.data == "x"));
}

#[tokio::test]
async fn malformed_utf8_does_not_accumulate_across_blocks() {
    let body = b"data: \xff\xe2\n\n".repeat(2000);
    let events = collect(body.into_iter().map(|b| vec![b]).collect(), 9)
        .await
        .unwrap();
    assert_eq!(events.len(), 2000);
    assert!(events.iter().all(|e| e.data == "\u{fffd}\u{fffd}"));
}

#[tokio::test]
async fn overflow_drops_source_before_yielding_without_waiting_for_eof() {
    for chunks in [vec![vec![b'x'; 17]], vec![vec![b'x'; 16], vec![b'x']]] {
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
        let mut decoded = Box::pin(Decoder::decode(source, 16));
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
async fn delivers_valid_event_before_terminal_overflow() {
    let body = format!("data: good\n\n{}", "x".repeat(33));
    let results: Vec<_> = Decoder::decode(stream::iter([Ok::<_, &str>(body)]), 32)
        .collect()
        .await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap().data, "good");
    results[1].as_ref().unwrap_err();
}

#[tokio::test]
async fn transport_error_terminates_and_eof_discards_partial_event() {
    let results: Vec<_> = Decoder::decode(
        stream::iter([Ok("data: x\n\n"), Err("broken"), Ok("data: never\n\n")]),
        32,
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
    for body in ["data: x", "data: x\n", "data: x\r", "data: x\r\n"] {
        assert!(
            collect(vec![body.as_bytes().to_vec()], 32)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn cr_terminated_event_does_not_wait_for_another_byte() {
    let source = stream::iter([Ok::<_, &str>("data: x\r\r")]).chain(stream::pending());
    let mut decoded = Box::pin(Decoder::decode(source, 32));
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
