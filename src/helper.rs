use super::structs::{
    Csrf, Data, ErrorEnum, Filters, KillerError, Payload, Progress, RequestPart, RequestParts,
    Settings,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Proxy, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

pub fn exit_with_err(err: KillerError) -> ! {
    log::error!("{}", err);
    std::process::exit(1);
}

pub fn validate_tokens(
    tokens: &Vec<String>,
) -> Result<HashMap<String, (String, Regex)>, KillerError> {
    let mut token_hashmap = HashMap::new();

    for token in tokens {
        let vt: Vec<&str> = token.split("==").collect();
        if vt.len() != 3 {
            return Err(KillerError {
                detail: Box::leak(
                    format!("Invalid token struct: {}, must be == separate", token)
                        .into_boxed_str(),
                ),
            });
        }
        token_hashmap.insert(
            vt.first().unwrap().to_string(),
            (
                // unwrap the unwrap
                vt.get(1).unwrap().to_string(),
                Regex::new(vt.get(2).unwrap()).unwrap(),
            ),
        );
    }
    Ok(token_hashmap)
}

pub fn validate_headers(headers: &Vec<String>) -> Result<HeaderMap, KillerError> {
    let mut header_map = HeaderMap::new();

    for header in headers {
        let pair: Vec<&str> = header.split(':').collect();
        if pair.len() != 2 {
            return Err(KillerError {
                detail: Box::leak(
                    format!("Invalid header: {}, must be : separate", header).into_boxed_str(),
                ),
            });
        }
        header_map.insert(
            HeaderName::from_str(pair.first().unwrap()).unwrap(),
            HeaderValue::from_str(pair.get(1).unwrap()).unwrap(),
        );
    }
    Ok(header_map)
}

pub fn validate_form(data: &str) -> Result<Option<Data>, KillerError> {
    let re = Regex::new(r"^([^=&]+=[^=&]+)(?:&[^=&]+=[^=&]+)*$").unwrap();

    if !re.is_match(data) {
        return Err(KillerError {
            detail: "Invalid format of form data",
        });
    }

    let spliting = data.split('&');

    let mut form_hashmap = HashMap::new();

    for field in spliting {
        let pair: Vec<&str> = field.split('=').collect();
        form_hashmap.insert(
            pair.first().unwrap().to_string(),
            pair.get(1).unwrap().to_string(),
        );
    }

    Ok(Some(Data::Form(form_hashmap)))
}

pub async fn get_lines(path: &str) -> Result<(Arc<Payload>, u64), KillerError> {
    let file = File::open(path).await.map_err(|_| KillerError {
        detail: "Cant open the wordlist",
    })?;

    let mut reader = BufReader::new(file).lines();
    let mut count = 0_u64;
    while reader.next_line().await.unwrap().is_some() {
        count += 1
    }

    let file = File::open(path).await.map_err(|_| KillerError {
        detail: "Cant open the wordlist",
    })?;

    Ok((
        Arc::new(Payload::Lines(Mutex::new(BufReader::new(file).lines()))),
        count,
    ))
}

pub fn create_client(settings: Arc<Settings>) -> Result<Client, KillerError> {
    let mut builder = reqwest::Client::builder();

    if settings.options.store_cookies {
        builder = builder.cookie_store(true);
    }
    if let Some(headers) = &settings.options.headers {
        builder = builder.default_headers(headers.clone());
    }

    if !settings.options.redirects {
        builder = builder.redirect(Policy::none())
    }

    if let Some(proxy) = &settings.options.proxy {
        builder = builder
            .proxy(Proxy::http(proxy).map_err(|_| KillerError {
                detail: "Invalid proxy",
            })?)
            .proxy(Proxy::https(proxy).map_err(|_| KillerError {
                detail: "Invalid proxy",
            })?)
    }

    // add comments
    builder = builder.danger_accept_invalid_certs(true);

    builder = builder.timeout(Duration::from_secs_f32(settings.options.timeout));

    Ok(builder.build().expect("Faild to build Client"))
}

pub fn filter_tokens(csrf: &Csrf, text: &str) -> Option<RequestParts> {
    let mut tokens = RequestParts::new();

    for (name, (position, re)) in csrf.tokens.iter() {
        let matched = re.captures(text)?.iter().last()?.as_ref()?.as_str();

        let token = match position.as_str() {
            "form" => {
                let mut hash_map = HashMap::new();
                hash_map.insert(name.to_string(), matched.to_string());
                RequestPart::Data(Data::Form(hash_map))
            }
            "json" => {
                let json_str = format!("{{\"{}\": \"{}\"}}", name, matched);
                RequestPart::Data(Data::Json(serde_json::from_str(&json_str).unwrap()))
            }
            "query" => RequestPart::Query(name.to_string(), matched.to_string()),
            "header" => RequestPart::Header(name.to_string(), matched.to_string()),
            "cookie" => {
                let cookie = format!("{}={}", name, matched);
                RequestPart::Cookie(cookie)
            }
            // KillerError?
            _ => panic!("Invalid token position"),
        };
        tokens.add(token);
    }
    Some(tokens)
}

pub async fn log_response(
    response: Result<Response, ErrorEnum>,
    filters: &Filters,
    payload: String,
    progress: Arc<Progress>,
) -> Result<(), KillerError> {
    let no = progress
        .no_req
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    match response {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let content_length = response.content_length().unwrap_or(0);
            let text = response.text().await.unwrap_or(String::new());
            let words = text.split_whitespace().count() as u64;
            let chars = text.chars().count() as u64;

            let fl = filters.status.map_or(false, |f| f == status_code)
                || filters.length.map_or(false, |f| f == content_length)
                || filters.words.map_or(false, |f| f == words)
                || filters.chars.map_or(false, |f| f == chars);

            if !fl {
                progress.pb.suspend(|| {
                    println!(
                        "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
                        no, status_code, content_length, words, chars, payload
                    );
                });
            }
        }
        Err(err) => match err {
            ErrorEnum::ReqwestError => {
                let no = progress
                    .no_err
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                progress.pb.set_message(no.to_string());
            }
            ErrorEnum::KillerError(err) => return Err(err),
        },
    }
    Ok(())
}

// https://stackoverflow.com/questions/47070876/how-can-i-merge-two-json-objects-with-rust
pub fn merge_json(a: &mut Value, b: Value) {
    match (a, b) {
        (a @ &mut Value::Object(_), Value::Object(b)) => {
            let a = a.as_object_mut().unwrap();
            for (k, v) in b {
                merge_json(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (a, b) => *a = b,
    }
}
