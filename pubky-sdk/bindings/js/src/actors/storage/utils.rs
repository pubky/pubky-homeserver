use crate::js_error::JsResult;
use futures_util::StreamExt;
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
use wasm_streams::ReadableStream;
use web_sys::{Headers, Response, ResponseInit};
#[cfg(target_arch = "wasm32")]
use web_sys::{Request, RequestCredentials, RequestInit};

#[cfg(target_arch = "wasm32")]
use crate::client::http::{js_fetch, map_fetch_error};
#[cfg(target_arch = "wasm32")]
use crate::js_error::{PubkyError, PubkyErrorName};

pub(crate) async fn apply_list_options(
    mut builder: pubky::ListBuilder<'_>,
    cursor: Option<String>,
    reverse: Option<bool>,
    limit: Option<u16>,
    shallow: Option<bool>,
) -> JsResult<Vec<String>> {
    if let Some(cursor) = cursor {
        builder = builder.cursor(&cursor);
    }
    if let Some(reverse) = reverse {
        builder = builder.reverse(reverse);
    }
    if let Some(limit) = limit {
        builder = builder.limit(limit);
    }
    if let Some(shallow) = shallow {
        builder = builder.shallow(shallow);
    }

    let entries = builder.send().await?;
    let urls = entries
        .into_iter()
        .map(|entry| entry.to_pubky_url())
        .collect();
    Ok(urls)
}

pub(crate) fn response_to_web_response(resp: reqwest::Response) -> JsResult<Response> {
    let status = resp.status();
    let headers_map = resp.headers().clone();

    let stream = resp.bytes_stream().map(|chunk| match chunk {
        Ok(bytes) => Ok(JsValue::from(Uint8Array::from(bytes.as_ref()))),
        Err(err) => Err(JsValue::from_str(&err.to_string())),
    });

    let readable_stream = ReadableStream::from_stream(stream);
    let web_stream = readable_stream.into_raw();

    let js_headers = Headers::new()?;
    for (name, value) in headers_map.iter() {
        let value_str = value
            .to_str()
            .map_err(|_| JsValue::from_str("invalid header value"))?;
        js_headers.append(name.as_str(), value_str)?;
    }

    let init = ResponseInit::new();
    init.set_status(status.as_u16());
    if let Some(reason) = status.canonical_reason() {
        init.set_status_text(reason);
    }
    let headers_value: JsValue = js_headers.into();
    init.set_headers(&headers_value);

    Response::new_with_opt_readable_stream_and_init(Some(&web_stream), &init).map_err(Into::into)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn send_blob_put(
    request: &reqwest::Request,
    body: &web_sys::Blob,
) -> JsResult<Response> {
    let headers = Headers::new()?;
    for (name, value) in request.headers() {
        let value = value
            .to_str()
            .map_err(|error| PubkyError::new(PubkyErrorName::RequestError, error))?;
        headers.append(name.as_str(), value)?;
    }
    let init = RequestInit::new();
    init.set_method("PUT");
    init.set_credentials(RequestCredentials::Include);
    init.set_headers(&headers);
    init.set_body(body);
    let request = Request::new_with_str_and_init(request.url().as_str(), &init)?;
    JsFuture::from(js_fetch(&request))
        .await
        .map_err(map_fetch_error)?
        .dyn_into::<Response>()
        .map_err(Into::into)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn check_web_http_status(
    response: web_sys::Response,
    limit: usize,
) -> JsResult<()> {
    let status = reqwest::StatusCode::from_u16(response.status())
        .map_err(|error| PubkyError::new(PubkyErrorName::RequestError, error))?;
    if status.is_success() {
        return Ok(());
    }
    let message = read_error_message(response, limit)
        .await
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .to_owned()
        });
    Err(pubky::Error::from(pubky::errors::RequestError::Server { status, message }).into())
}

#[cfg(target_arch = "wasm32")]
async fn read_error_message(response: Response, limit: usize) -> Option<String> {
    let Some(body) = response.body() else {
        return (limit > 0).then(String::new);
    };
    let mut chunks = ReadableStream::from_raw(body).try_into_stream().ok()?;
    if limit == 0 {
        return None;
    }

    let mut captured = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = chunks.next().await {
        let chunk = Uint8Array::new(&chunk.ok()?);
        let remaining = limit - captured.len();
        let count = (chunk.length() as usize).min(remaining);
        captured.extend_from_slice(&chunk.subarray(0, count as u32).to_vec());
        if chunk.length() as usize > remaining {
            truncated = true;
            break;
        }
    }
    drop(chunks);

    let captured = captured.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&captured);
    let mut message = String::from_utf8_lossy(captured).into_owned();
    if truncated {
        message.push_str(&format!("\n[response body truncated at {limit} bytes]"));
    }
    Some(message)
}
