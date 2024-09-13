use super::helper::{create_client, filter_tokens, get_lines, log_response};
use super::structs::{
    Csrf, Data, Payload, Progress, RequestPart, RequestParts, Settings, Target, ErrorEnum, KillerError
};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, Response};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

pub async fn create_poll(settings: Arc<Settings>) -> Result<(), KillerError> {
    let (payload, total_req) = if settings.brute_force {
        // if brute force mode wordlist is requeres so
        get_lines(settings.wordlist.as_ref().unwrap()).await?
    } else {
        (Arc::new(Payload::Future), 0_u64)
    };

    println!(
        "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
        "#", "Status", "Length", "Words", "Chars", "Payload"
    );

    let progress = Arc::new(Progress {
        pb: ProgressBar::new(total_req),
        no_req: AtomicU32::new(1),
        no_err: AtomicU32::new(1),
    });

    progress.pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {percent}% [{bar:50.cyan/blue}] \
            {pos:.cyan}/{len:.blue} [Errors: {msg:.red}] [ETA: {eta_precise}]",
        )
        .expect("Error in load template to progress bar")
        .progress_chars("=>-"),
    );
    progress.pb.enable_steady_tick(Duration::from_millis(100));
    progress.pb.set_message("0");

    let mut workers = Vec::new();
    for _ in 0..settings.concurrence {
        workers.push(tokio::spawn(worker(
            Arc::clone(&payload),
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

async fn worker(
    payload: Arc<Payload>,
    settings: Arc<Settings>,
    progress: Arc<Progress>,
) -> Result<(), KillerError> {
    let client = create_client(Arc::clone(&settings))?;

    match *payload {
        Payload::Lines(ref lines) => loop {
            let line = {
                let mut lines = lines.lock().await;
                lines.next_line().await.unwrap()
            };
            if let Some(ln) = line {
                let response = repeater(Arc::clone(&settings), client.clone(), &ln).await;
                log_response(response, &settings.filters, ln, Arc::clone(&progress)).await?;
                progress.pb.inc(1);
                std::thread::sleep(Duration::from_millis(5));
            } else {
                break;
            }
        },
        _ => todo!(),
    }
    Ok(())
}

async fn repeater(
    settings: Arc<Settings>,
    client: Client,
    line: &str,
) -> Result<Response, ErrorEnum> {
    let mut request_parts = RequestParts::new();

    if let Some(tokens) = csrf_request(client.clone(), &settings.csrf).await? {
        request_parts.extend(tokens);
    } else {
        return Err(KillerError {
            detail: "Not found a value for the provided regexes",
        }
        .into());
    }

    target_request(client, &settings.target, request_parts, line).await
}

async fn csrf_request(client: Client, csrf: &Csrf) -> Result<Option<RequestParts>, ErrorEnum> {
    let response = client.get(&csrf.url).send().await?;
    let text = response.text().await?;
    Ok(filter_tokens(csrf, &text))
}

async fn target_request(
    client: Client,
    target: &Target,
    mut request_parts: RequestParts,
    line: &str,
) -> Result<Response, ErrorEnum> {
    let url = &target.url.replace("FUZZ", line);
    let mut builder = match target.method.as_str() {
        "get" => client.get(url),
        "post" => client.post(url),
        "put" => client.put(url),
        "delete" => client.delete(url),
        _ => panic!(),
    };

    match &target.data {
        Some(Data::Form(ref form_data)) => {
            let mut form_data = form_data.clone();
            form_data
                .iter_mut()
                .for_each(|(_, v)| *v = v.replace("FUZZ", line));
            request_parts.add(RequestPart::Data(Data::Form(form_data)))
        }
        Some(Data::Json(ref json_data)) => {
            let json_str = json_data.clone().to_string().replace("FUZZ", line);
            request_parts.add(RequestPart::Data(Data::Json(
                serde_json::from_str(&json_str).unwrap(),
            )))
        }
        None => (),
    };

    request_parts.join_parts();

    for part in &request_parts.values {
        builder = match part {
            RequestPart::Data(Data::Json(json)) => builder.json(json),
            RequestPart::Data(Data::Form(form)) => builder.form(form),
            RequestPart::Query(s1, s2) => builder.query(&[(s1, s2)]),
            RequestPart::Header(s1, s2) => builder.header(s1, s2),
            RequestPart::Cookie(cookie) => builder.header("Cookie", cookie),
        }
    }

    Ok(builder.send().await?)
}
