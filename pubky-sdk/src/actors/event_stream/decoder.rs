//! SSE decoding with a byte limit per block.

use std::fmt::Display;

use eventsource_stream::Event;
use futures_util::{Stream, StreamExt, stream};

use crate::errors::{RequestError, Result};

#[derive(Debug)]
pub(super) struct Decoder {
    limit: usize,
    block_bytes: usize,
    line: Vec<u8>,
    event: Event,
    first_line: bool,
    after_cr: bool,
    count_lf: bool,
}

impl Decoder {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            block_bytes: 0,
            line: Vec::new(),
            event: Event::default(),
            first_line: true,
            after_cr: false,
            count_lf: false,
        }
    }

    fn count_byte(&mut self) -> Result<()> {
        if self.block_bytes == self.limit {
            return Err(RequestError::Validation {
                message: format!(
                    "SSE event exceeds the configured limit of {} bytes",
                    self.limit
                ),
            }
            .into());
        }
        self.block_bytes += 1;
        Ok(())
    }

    fn push(&mut self, byte: u8) -> Result<Option<Event>> {
        if std::mem::take(&mut self.after_cr) && byte == b'\n' {
            if self.count_lf {
                self.count_byte()?;
            }
            return Ok(None);
        }

        if byte != b'\r' && byte != b'\n' {
            self.count_byte()?;
            self.line.push(byte);
            return Ok(None);
        }

        let bom_bytes =
            if std::mem::take(&mut self.first_line) && self.line.starts_with(b"\xef\xbb\xbf") {
                3
            } else {
                0
            };
        let empty = self.line.len() == bom_bytes;
        self.after_cr = byte == b'\r';
        self.count_lf = !empty;

        if empty {
            self.line.clear();
            self.block_bytes = 0;
            let mut event = std::mem::take(&mut self.event);
            if event.data.is_empty() {
                return Ok(None);
            }
            event.data.pop(); // Remove the last data field's appended newline.
            if event.event.is_empty() {
                event.event = "message".into();
            }
            return Ok(Some(event));
        }

        // Count the line ending before allocating decoded text. Decode complete
        // lines so invalid UTF-8 cannot accumulate across blocks.
        self.count_byte()?;
        let line = String::from_utf8_lossy(&self.line[bom_bytes..]);
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => {
                self.event.event.clear();
                self.event.event.push_str(value);
            }
            "data" => {
                self.event.data.push_str(value);
                self.event.data.push('\n');
            }
            // Unused fields and comments still count toward the limit.
            _ => {}
        }
        self.line.clear();
        Ok(None)
    }

    /// `try_unfold` drops the source before yielding an error, even if the caller
    /// retains the stream without polling it again.
    pub(super) fn decode<S, B, E>(source: S, limit: usize) -> impl Stream<Item = Result<Event>>
    where
        S: Stream<Item = std::result::Result<B, E>>,
        B: AsRef<[u8]>,
        E: Display,
    {
        let state = (Box::pin(source), None::<B>, 0, Self::new(limit));
        stream::try_unfold(
            state,
            |(mut source, mut chunk, mut offset, mut decoder)| async move {
                let mut processed = 0;
                loop {
                    if let Some(bytes) = &chunk {
                        while offset < bytes.as_ref().len() {
                            let byte = bytes.as_ref()[offset];
                            offset += 1;
                            if let Some(event) = decoder.push(byte)? {
                                return Ok(Some((event, (source, chunk, offset, decoder))));
                            }
                            processed += 1;
                            if processed == 64 * 1024 {
                                // A peer can send unlimited comment-only blocks. Yield
                                // cooperatively even when the source is always ready.
                                futures_lite::future::yield_now().await;
                                processed = 0;
                            }
                        }
                    }
                    drop(chunk.take());
                    match source.next().await {
                        Some(bytes) => {
                            chunk = Some(bytes.map_err(|error| RequestError::Validation {
                                message: format!("SSE stream error: {error}"),
                            })?);
                            offset = 0;
                        }
                        None => return Ok(None), // SSE discards an incomplete event at EOF.
                    }
                }
            },
        )
    }
}

#[cfg(test)]
mod tests;
