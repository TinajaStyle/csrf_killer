use super::helper::{create_client, exit_with_err, filter_tokens, get_lines, log_response};
use super::structs::{
    Csrf, Data, Payload, Progress, RequestPart, RequestParts, Settings, Target,
};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, Response};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

pub async fn create_poll(settings: Arc<Settings>) {
    let (payload, total_req) = if settings.brute_force {
        // if brute force mode wordlist is requeres so
        get_lines(settings.wordlist.as_ref().unwrap()).await
    } else {
        (Arc::new(Payload::Future), 0_u64)
    };

    println!(
        "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
        "#", "Status", "Length", "Words", "Chars", "Payload"
    );

    let progress = Arc::new(Progress {
        pb: ProgressBar::new(total_req),
        no: AtomicU32::new(1),
    });

    progress.pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {percent}% [{bar:50.cyan/blue}] {pos:.cyan}/{len:.blue} [ETA: {eta_precise}]")
            .expect("Error in load template to progress bar")
            .progress_chars("=>-")
        );
    progress.pb.enable_steady_tick(Duration::from_millis(100));

    let mut workers = Vec::new();
    for _ in 0..settings.concurrence {
        workers.push(tokio::spawn(worker(
            Arc::clone(&payload),
            Arc::clone(&settings),
            Arc::clone(&progress),
        )));
    }

    for wk in workers {
        let _ = wk.await;
    }

    progress.pb.finish();
}

async fn worker(payload: Arc<Payload>, settings: Arc<Settings>, progress: Arc<Progress>) {
    let client = create_client(Arc::clone(&settings));

    match *payload {
        Payload::Lines(ref lines) => loop {
            let line = {
                let mut lines = lines.lock().await;
                lines.next_line().await.unwrap()
            };
            match line {
                Some(ln) => {
                    let no = progress
                        .no
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let response = repeater(Arc::clone(&settings), client.clone(), &ln).await;
                    log_response(response, &settings.filters, ln, no, &progress.pb).await;
                    progress.pb.inc(1);
                    std::thread::sleep(Duration::from_millis(5));
                }
                None => break,
            };
        },
        _ => todo!(),
    }
}

async fn repeater(settings: Arc<Settings>, client: Client, line: &str) -> Response {
    let mut request_parts = RequestParts::new();

    if let Some(tokens) = csrf_request(client.clone(), &settings.csrf).await {
        request_parts.extend(tokens);
    } else {
        exit_with_err("Not found a value for the provided regexes", None);
    }

    target_request(client, &settings.target, request_parts, line).await
}

async fn csrf_request(client: Client, csrf: &Csrf) -> Option<RequestParts> {
    let response = client.get(&csrf.url).send().await.unwrap();
    let text = response.text().await.unwrap();
    filter_tokens(csrf, &text)
}

async fn target_request(
    client: Client,
    target: &Target,
    mut request_parts: RequestParts,
    line: &str,
) -> Response {
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

    builder.send().await.unwrap()
}
