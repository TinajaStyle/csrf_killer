use super::helper::{create_client, filter_tokens, get_lines, get_part_file, log_response};
use super::structs::{
    Csrf, Data, ErrorEnum, KillerError, Payload, Progress, RequestPart, RequestParts, Settings,
    Target,
};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{multipart, Client, Response};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{BufReader, Lines};
use tokio::sync::Mutex;

/// Gets the lines of the given file to distribute them by workers.
///
/// Initializes the progress bar.
pub async fn create_workers(settings: Arc<Settings>) -> Result<(), KillerError> {
    let (lines, total_req) = if settings.modes.brute_force {
        // if brute force mode is true, wordlist is requeres then
        get_lines(settings.modes.wordlist.as_ref().unwrap()).await?
    } else if settings.modes.upload_files {
        // if file upload mode is true, file_paths is required then
        get_lines(settings.modes.file_paths.as_ref().unwrap()).await?
    } else {
        todo!()
    };

    println!(
        "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
        "#", "Status", "Length", "Lines", "Words", "Payload"
    );

    let progress = Arc::new(Progress {
        pb: ProgressBar::new(total_req * settings.repeat as u64),
        no_req: AtomicUsize::new(1),
        no_err: AtomicUsize::new(1),
    });

    progress.pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {percent}% [{bar:50.cyan/blue}] \
            {pos:.cyan}/{len:.blue} [Errors: {msg:.red}] [ETA: {eta_precise}]",
        )
        .expect("Error loading template in progress bar")
        .progress_chars("=>-"),
    );
    progress.pb.enable_steady_tick(Duration::from_millis(100));
    progress.pb.set_message("0");

    let mut workers = Vec::new();
    for _ in 0..settings.concurrence {
        workers.push(tokio::spawn(worker(
            Arc::clone(&lines),
            Arc::clone(&settings),
            Arc::clone(&progress),
        )));
    }

    for wk in workers {
        wk.await.unwrap()?;
    }

    progress.pb.finish();
    Ok(())
}

/// This continuously tries to read a line from the file, if it exists it starts the attack and log
/// the response otherwise it stop.
async fn worker(
    lines: Arc<Mutex<Lines<BufReader<File>>>>,
    settings: Arc<Settings>,
    progress: Arc<Progress>,
) -> Result<(), KillerError> {
    let client = create_client(&settings.options)?;

    loop {
        let opline = {
            let mut lines = lines.lock().await;
            lines.next_line().await.unwrap()
        };
        if let Some(line) = opline {
            let payload = if settings.modes.brute_force {
                Payload::Line(&line)
            } else {
                Payload::Upload(settings.modes.field_name.as_ref().unwrap(), &line)
            };

            for _ in 0..settings.repeat {
                let response = repeater(Arc::clone(&settings), client.clone(), &payload).await;
                log_response(response, &settings.filters, &line, Arc::clone(&progress)).await?;
            }
            progress.pb.inc(1);
            tokio::time::sleep(Duration::from_secs_f32(settings.delay)).await;
        } else {
            break;
        }
    }
    Ok(())
}

/// Request to the csrf url and exploit to the target url.
async fn repeater(
    settings: Arc<Settings>,
    client: Client,
    payload: &Payload<'_>,
) -> Result<Response, ErrorEnum> {
    let mut request_parts = RequestParts::new();

    let tokens = csrf_request(client.clone(), &settings.csrf).await?;
    request_parts.extend(tokens);

    target_request(client, &settings.target, request_parts, payload).await
}

/// Make a request to the given url to get the token(s).
///
/// # Error
///
/// if dont found a value for a regex for a token or request fail.
async fn csrf_request(client: Client, csrf: &Csrf) -> Result<RequestParts, ErrorEnum> {
    let response = client.get(&csrf.url).send().await?;
    let text = response.text().await?;
    Ok(filter_tokens(csrf, &text)?)
}

/// For the payload Line change the FUZZ keyword to this one and make the request.
///
/// For the payload Upload takes the contents of the file and sends it by multipart.
///
/// # Errors
///
/// If the file can't be opened or the request fail.
async fn target_request(
    client: Client,
    target: &Target,
    mut request_parts: RequestParts,
    payload: &Payload<'_>,
) -> Result<Response, ErrorEnum> {
    let url = match *payload {
        Payload::Line(line) => {
            request_parts.add_fuzz_data(target.data.as_ref(), line);
            target.url.replace("FUZZ", line)
        }
        Payload::Upload(field_name, path) => {
            let part = get_part_file(field_name, path).await?;
            request_parts.add(part);
            target.url.clone()
        }
    };
    let mut builder = match target.method.as_str() {
        "get" => client.get(url),
        "post" => client.post(url),
        "put" => client.put(url),
        "delete" => client.delete(url),
        _ => unreachable!(),
    };

    request_parts.join_parts();

    let mut multipart_data = multipart::Form::new();
    let mut found_multipart = false;

    for part in request_parts.values {
        builder = match part {
            RequestPart::Query(s1, s2) => builder.query(&[(s1, s2)]),
            RequestPart::Header(s1, s2) => builder.header(s1, s2),
            RequestPart::Cookie(cookie) => builder.header("Cookie", cookie),
            RequestPart::Data(Data::Json(json)) => builder.json(&json),
            RequestPart::Data(Data::Form(form)) => builder.form(&form),
            RequestPart::Data(Data::File(field_name, name, mime, data)) => {
                let part = multipart::Part::bytes(data)
                    .file_name(name)
                    .mime_str(&mime)?;
                multipart_data = multipart_data.part(field_name, part);
                found_multipart = true;
                builder
            }
            RequestPart::Data(Data::PartText(data)) => {
                for (name, value) in data {
                    multipart_data = multipart_data.text(name, value);
                }
                found_multipart = true;
                builder
            }
        }
    }

    if found_multipart {
        builder = builder.multipart(multipart_data)
    };

    Ok(builder.send().await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_csrf() {
        let client = reqwest::Client::new();

        let url = "http://localhost:8888/get-csrf".to_string();
        let mut token = HashMap::new();
        token.insert(
            "token".to_string(),
            ("form".to_string(), Regex::new("_token=([^<]+)").unwrap()),
        );

        let csrf = Csrf { url, tokens: token };

        let result = csrf_request(client, &csrf).await;

        match result {
            Ok(request_parts) => {
                assert_eq!(request_parts.values.len(), 1);
                let mut token = HashMap::new();
                token.insert("token".to_string(), "fjlalksdjfaksdj".to_string());

                match &request_parts.values[0] {
                    RequestPart::Data(Data::Form(response_token)) => {
                        assert_eq!(response_token, &token)
                    }
                    _ => panic!("Do not recieve the enum that we want"),
                }
            }
            Err(ErrorEnum::ReqwestError(err)) => panic!("Reqwest error: {}", err),
            Err(ErrorEnum::KillerError(err)) => panic!("KillerError: {}", err),
        }
    }

    fn create_request_parts(data_type: &str) -> RequestParts {
        let mut request_parts = RequestParts::new();
        let mut token = HashMap::new();
        token.insert("token".to_string(), "fjlalksdjfaksdj".to_string());
        match data_type {
            "Form" => request_parts.add(RequestPart::Data(Data::Form(token))),
            "PartText" => request_parts.add(RequestPart::Data(Data::PartText(token))),
            _ => unreachable!(),
        }
        request_parts
    }

    fn handle_result(result: Result<Response, ErrorEnum>) {
        match result {
            Ok(response) => assert_eq!(response.status(), 200),
            Err(ErrorEnum::KillerError(err)) => panic!("Error in request: {}", err),
            Err(ErrorEnum::ReqwestError(err)) => panic!("Error in request: {}", err),
        }
    }

    #[tokio::test]
    async fn test_target_login() {
        let client = reqwest::Client::new();

        let url = "http://localhost:8888/login/form".to_string();
        let method = "post".to_string();

        let mut data_hash = HashMap::new();
        data_hash.insert("username".to_string(), "admin".to_string());
        data_hash.insert("password".to_string(), "FUZZ".to_string());
        let data = Some(Data::Form(data_hash));

        let target = Target { url, method, data };

        let request_parts = create_request_parts("Form");

        let payload = Payload::Line("123123");

        let result = target_request(client, &target, request_parts, &payload).await;
        handle_result(result);
    }

    #[tokio::test]
    async fn test_target_upload() {
        let client = reqwest::Client::new();

        let url = "http://localhost:8888/upload/file".to_string();
        let method = "post".to_string();

        let target = Target {
            url,
            method,
            data: None,
        };

        let request_parts = create_request_parts("PartText");

        let payload = Payload::Upload("upload_file", "Cargo.toml");

        let result = target_request(client, &target, request_parts, &payload).await;
        handle_result(result);
    }
}
