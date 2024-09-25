use super::structs::{
    Csrf, Data, ErrorEnum, Filters, KillerError, Progress, RequestOptions, RequestPart,
    RequestParts,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Proxy, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{atomic::Ordering::Relaxed, Arc};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Lines};
use tokio::sync::Mutex;

pub fn art() {
    let ascii = r#""

        .·:'''''''''''''''''''''''''''''''''''''''''''''''''':·.
        : :   ___  __  ___ ___   _  ___ _   _   _   ___ ___  : :
        : :  / _//' _/| _ \ __| | |/ / | | | | | | | __| _ \ : :
        : : | \__`._`.| v / _|  |   <| | |_| |_| |_| _|| v / : :
        : :  \__/|___/|_|_\_|   |_|\_\_|___|___|___|___|_|_\ : :
        '·:..................................................:·'
     "#;

    println!("{ascii}");
}

pub fn exit_with_err(err: KillerError) -> ! {
    log::error!("{}", err);
    println!();
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
                    format!("Invalid token struct: {}, must be == separated", token)
                        .into_boxed_str(),
                ),
            });
        }
        token_hashmap.insert(
            vt.first().unwrap().to_string(),
            (
                vt.get(1).unwrap().to_string(),
                Regex::new(vt.get(2).unwrap()).map_err(|err| KillerError {
                    detail: Box::leak(format!("Invalid Regex: {}", err).into_boxed_str()),
                })?,
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
                    format!("Invalid header: {}, must be : separated", header).into_boxed_str(),
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

pub fn validate_form(data: &str) -> Result<HashMap<String, String>, KillerError> {
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

    Ok(form_hashmap)
}

pub async fn get_lines(
    path: &str,
) -> Result<(Arc<Mutex<Lines<BufReader<File>>>>, u64), KillerError> {
    let file = File::open(path).await.map_err(|_| KillerError {
        detail: "Can't open the wordlist",
    })?;

    let mut reader = BufReader::new(file).lines();
    let mut count = 0_u64;
    while reader.next_line().await.unwrap().is_some() {
        count += 1
    }

    let file = File::open(path).await.map_err(|_| KillerError {
        detail: "Can't open the wordlist",
    })?;

    let a = BufReader::new(file).lines();
    Ok((Arc::new(Mutex::new(a)), count))
}

/// Creates the ClientBuilder according to the given options.
pub fn create_client(options: &RequestOptions) -> Result<Client, KillerError> {
    let mut builder = reqwest::Client::builder();

    if options.store_cookies {
        builder = builder.cookie_store(true);
    }
    if let Some(headers) = &options.headers {
        builder = builder.default_headers(headers.clone());
    }

    if !options.redirects {
        builder = builder.redirect(Policy::none())
    }

    if let Some(proxy) = &options.proxy {
        builder = builder
            .proxy(Proxy::http(proxy).map_err(|_| KillerError {
                detail: "Invalid proxy",
            })?)
            .proxy(Proxy::https(proxy).map_err(|_| KillerError {
                detail: "Invalid proxy",
            })?)
    }

    // should there be an arg?
    builder = builder.danger_accept_invalid_certs(true);

    // default 5
    builder = builder.timeout(Duration::from_secs_f32(options.timeout));

    builder.build().map_err(|_| KillerError {
        detail: "Faild to build the Client",
    })
}

pub fn filter_tokens(csrf: &Csrf, text: &str) -> Result<RequestParts, KillerError> {
    let mut tokens = RequestParts::new();

    for (name, (position, re)) in csrf.tokens.iter() {
        let matched = re
            .captures(text)
            .ok_or(KillerError {
                detail: Box::leak(
                    format!("Don't found a match for the regex of the token: {}", name)
                        .into_boxed_str(),
                ),
            })?
            .iter()
            .last()
            .ok_or(KillerError {
                detail: "Can not get the last group of the regex",
            })?
            .ok_or(KillerError {
                detail: "Can not get the value of the last group of the regex",
            })?
            .as_str();

        let token = match position.as_str() {
            "form" => {
                let mut hash_map = HashMap::new();
                hash_map.insert(name.to_string(), matched.to_string());
                RequestPart::Data(Data::Form(hash_map))
            }
            "multipart" => {
                let mut hash_map = HashMap::new();
                hash_map.insert(name.to_string(), matched.to_string());
                RequestPart::Data(Data::PartText(hash_map))
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
            _ => {
                return Err(KillerError {
                    detail: "Invalid token position",
                })
            }
        };
        tokens.add(token);
    }
    Ok(tokens)
}

pub async fn get_part_file(field_name: &str, path: &str) -> Result<RequestPart, KillerError> {
    let mut file = File::open(path).await.map_err(|_| KillerError {
        detail: Box::leak(format!("Error open the file: {}", path).into_boxed_str()),
    })?;
    let mut buffer = Vec::new();
    let _ = file
        .read_to_end(&mut buffer)
        .await
        .map_err(|_| KillerError {
            detail: Box::leak(format!("Error read the file: {}", path).into_boxed_str()),
        })?;
    let mime = mime_guess::from_path(path).first_or_text_plain();

    // The file was open and if dont exist KillerError is returned so unwrap is ok
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    Ok(RequestPart::Data(Data::File(
        field_name.to_string(),
        name,
        mime.to_string(),
        buffer,
    )))
}

pub async fn log_response(
    response: Result<Response, ErrorEnum>,
    filters: &Filters,
    payload: String,
    progress: Arc<Progress>,
) -> Result<(), KillerError> {
    let no = progress.no_req.fetch_add(1, Relaxed);

    match response {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let content_length = response.content_length().unwrap_or(0);
            let text = response.text().await.unwrap_or(String::new());
            let lines = text.lines().count();
            let words = text.split_whitespace().count();

            let fl = filters.status.map_or(false, |f| f == status_code)
                || filters.length.map_or(false, |f| f == content_length)
                || filters.words.map_or(false, |f| f == words)
                || filters.lines.map_or(false, |f| f == lines);

            if !fl {
                progress.pb.suspend(|| {
                    println!(
                        "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
                        no, status_code, content_length, lines, words, payload
                    );
                });
            }
        }
        Err(err) => match err {
            ErrorEnum::ReqwestError(_) => {
                let no = progress.no_err.fetch_add(1, Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_tokens() {
        let vec = vec!["token==form==a(.*?)b".to_string()];
        let result = validate_tokens(&vec);
        assert!(result.is_ok());

        // unclose regex group
        let vec = vec!["token==form==a(.*?b".to_string()];
        let result = validate_tokens(&vec);
        assert!(result.is_err());

        // invalid separator
        let vec = vec!["token==form=a(.*?)b".to_string()];
        let result = validate_tokens(&vec);
        assert!(result.is_err())
    }
}
