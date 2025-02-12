use anyhow::Result;
use chrono::Local;
use futures::future::join_all;
use md5::{Digest, Md5};
use reqwest::{StatusCode, Url};
use scraper::{Html, Selector};
use std::{
    collections::HashSet,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tokio::{
    fs,
    sync::{mpsc, Mutex as TokioMutex, Semaphore},
};

/// Helper function to normalize a URL string.
/// If the URL does not start with "http://" or "https://", it prepends "http://".
fn normalize_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url)
    }
}

/// Writes a log message with a timestamp into "log/antivirus.log".
fn log_message(message: &str) -> std::io::Result<()> {
    use std::io::Write;
    let log_dir = "log";
    std::fs::create_dir_all(log_dir)?;
    let log_file = Path::new(log_dir).join("antivirus.log");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    writeln!(
        file,
        "{} - {}",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        message
    )?;
    Ok(())
}

/// Holds the domain lists loaded from files.
struct DomainCollections {
    malware_domains: HashSet<String>,
    malware_domains_mail: HashSet<String>,
    phishing_domains: HashSet<String>,
    abuse_domains: HashSet<String>,
    mining_domains: HashSet<String>,
    spam_domains: HashSet<String>,
    malware_sub_domains: HashSet<String>,
    malware_mail_sub_domains: HashSet<String>,
    phishing_sub_domains: HashSet<String>,
    abuse_sub_domains: HashSet<String>,
    mining_sub_domains: HashSet<String>,
    spam_sub_domains: HashSet<String>,
}

impl DomainCollections {
    /// Returns the union of all domains.
    fn union_all(&self) -> HashSet<String> {
        let mut union = HashSet::new();
        union.extend(self.malware_domains.iter().cloned());
        union.extend(self.malware_domains_mail.iter().cloned());
        union.extend(self.phishing_domains.iter().cloned());
        union.extend(self.abuse_domains.iter().cloned());
        union.extend(self.mining_domains.iter().cloned());
        union.extend(self.spam_domains.iter().cloned());
        union.extend(self.malware_sub_domains.iter().cloned());
        union.extend(self.malware_mail_sub_domains.iter().cloned());
        union.extend(self.phishing_sub_domains.iter().cloned());
        union.extend(self.abuse_sub_domains.iter().cloned());
        union.extend(self.mining_sub_domains.iter().cloned());
        union.extend(self.spam_sub_domains.iter().cloned());
        union
    }
}

/// Loads a file’s (line‑oriented) contents into a HashSet.
/// Each line is trimmed and converted to lowercase.
/// If the file does not exist, returns an empty set.
fn load_lines(path: &Path) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim().to_lowercase();
            if !trimmed.is_empty() {
                set.insert(trimmed);
            }
        }
    }
    Ok(set)
}

/// Loads all required domain lists from the given website directory.
fn load_domain_collections(website_dir: &Path) -> Result<DomainCollections> {
    Ok(DomainCollections {
        malware_domains: load_lines(&website_dir.join("MalwareDomains.txt"))?,
        malware_domains_mail: load_lines(&website_dir.join("MalwareDomainsMail.txt"))?,
        phishing_domains: load_lines(&website_dir.join("PhishingDomains.txt"))?,
        abuse_domains: load_lines(&website_dir.join("AbuseDomains.txt"))?,
        mining_domains: load_lines(&website_dir.join("MiningDomains.txt"))?,
        spam_domains: load_lines(&website_dir.join("SpamDomains.txt"))?,
        malware_sub_domains: load_lines(&website_dir.join("MalwareSubDomains.txt"))?,
        malware_mail_sub_domains: load_lines(&website_dir.join("MalwareSubDomainsMail.txt"))?,
        phishing_sub_domains: load_lines(&website_dir.join("PhishingSubDomains.txt"))?,
        abuse_sub_domains: load_lines(&website_dir.join("AbuseSubDomains.txt"))?,
        mining_sub_domains: load_lines(&website_dir.join("MiningDomains.txt"))?,
        spam_sub_domains: load_lines(&website_dir.join("SpamSubDomains.txt"))?,
    })
}

/// Holds the whitelist sets loaded from files.
struct WhiteListCollections {
    domains: HashSet<String>,
    sub_domains: HashSet<String>,
    domains_mail: HashSet<String>,
    sub_domains_mail: HashSet<String>,
    ipv4: HashSet<String>,
    ipv6: HashSet<String>,
}

/// Loads all whitelist files from the given directory.
fn load_whitelist_collections(website_dir: &Path) -> Result<WhiteListCollections> {
    Ok(WhiteListCollections {
        domains: load_lines(&website_dir.join("WhiteListDomains.txt"))?,
        sub_domains: load_lines(&website_dir.join("WhiteListSubDomains.txt"))?,
        domains_mail: load_lines(&website_dir.join("WhiteListDomainsMail.txt"))?,
        sub_domains_mail: load_lines(&website_dir.join("WhiteListSubDomainsMail.txt"))?,
        ipv4: load_lines(&website_dir.join("IPv4WhiteList.txt"))?, // Ensure file name is correct
        ipv6: load_lines(&website_dir.join("IPv6WhiteList.txt"))?,
    })
}

/// Returns true if the given host (normalized to lowercase) is whitelisted.
fn is_whitelisted(host: &str, whitelist: &WhiteListCollections) -> bool {
    let host = host.to_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(_) => return whitelist.ipv4.contains(&host),
            IpAddr::V6(_) => return whitelist.ipv6.contains(&host),
        }
    }
    if whitelist.domains.contains(&host) || whitelist.domains_mail.contains(&host) {
        return true;
    }
    for sub in &whitelist.sub_domains {
        if host == *sub || host.ends_with(&format!(".{}", sub)) {
            return true;
        }
    }
    for sub in &whitelist.sub_domains_mail {
        if host == *sub || host.ends_with(&format!(".{}", sub)) {
            return true;
        }
    }
    false
}

/// A simple Task: a URL and its recursion depth.
struct Task {
    url: String,
    depth: usize,
}

/// Holds the result of processing one URL.
struct ProcessResult {
    new_urls: Vec<String>,
}

/// Extracts a filename from a Content-Disposition header value.
fn extract_filename(content_disp: &str) -> Option<String> {
    let lower = content_disp.to_lowercase();
    if let Some(index) = lower.find("filename=") {
        let start = index + "filename=".len();
        let remainder = &content_disp[start..];
        let filename = if remainder.starts_with('"') {
            let after_quote = &remainder[1..];
            if let Some(end_quote) = after_quote.find('"') {
                &after_quote[..end_quote]
            } else {
                after_quote
            }
        } else {
            let end = remainder.find(|c: char| c == ';' || c.is_whitespace()).unwrap_or(remainder.len());
            &remainder[..end]
        };
        Some(filename.to_string())
    } else {
        None
    }
}

/// Queries the MD5 API online for a given MD5 hash (in uppercase).
async fn query_md5_online(client: &reqwest::Client, md5: &str) -> Result<(String, String)> {
    let url = format!("https://www.nictasoft.com/ace/md5/{}", md5);
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Ok(("Unknown (API error)".to_string(), "".to_string()));
    }
    let text = response.text().await?;
    let lower_text = text.to_lowercase();
    if lower_text.contains("[100% risk]") {
        if let Some(pos) = lower_text.find("detected as") {
            let after = &text[pos + "detected as".len()..];
            let virus_name = after.trim().split_whitespace().next().unwrap_or("").to_string();
            return Ok(("Malware".to_string(), virus_name));
        }
        return Ok(("Malware".to_string(), "".to_string()));
    } else if lower_text.contains("[70% risk]") {
        if let Some(pos) = lower_text.find("detected as") {
            let after = &text[pos + "detected as".len()..];
            let virus_name = after.trim().split_whitespace().next().unwrap_or("").to_string();
            return Ok(("Suspicious".to_string(), virus_name));
        }
        return Ok(("Suspicious".to_string(), "".to_string()));
    } else if lower_text.contains("[0% risk]") {
        return Ok(("Benign".to_string(), "".to_string()));
    } else if lower_text.contains("[10% risk]") {
        return Ok(("Benign (auto verdict)".to_string(), "".to_string()));
    } else if lower_text.contains("this file is not yet rated") {
        return Ok(("Unknown".to_string(), "".to_string()));
    }
    Ok(("Unknown (Result)".to_string(), "".to_string()))
}

/// Processes a URL. If its host is whitelisted, the URL is skipped.
/// Otherwise, if not HTML, it downloads and (if malicious) saves the file;
/// if HTML, it extracts new URLs.
async fn process_url(
    url: String,
    depth: usize,
    client: Arc<reqwest::Client>,
    collections: Arc<DomainCollections>,
    whitelist: Arc<WhiteListCollections>,
    zeroday_dir: Arc<PathBuf>,
    processed: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
) -> ProcessResult {
    let _permit = semaphore.acquire().await;
    let start_msg = format!("Processing URL (depth {}): {}", depth, url);
    let _ = log_message(&start_msg);

    {
        let mut proc_lock = processed.lock().unwrap();
        if proc_lock.contains(&url) {
            return ProcessResult { new_urls: vec![] };
        }
        proc_lock.insert(url.clone());
    }

    let normalized_url = normalize_url(&url);

    if let Ok(parsed) = Url::parse(&normalized_url) {
        if let Some(host) = parsed.host_str() {
            if is_whitelisted(host, &whitelist) {
                let msg = format!("Skipping whitelisted URL: {}", normalized_url);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
        }
    }

    let resp = match client.get(&normalized_url).timeout(Duration::from_secs(10)).send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Error downloading {}: {}", normalized_url, e);
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }
    };

    if resp.status() != StatusCode::OK {
        let msg = format!("Failed to download {} (status: {})", normalized_url, resp.status());
        let _ = log_message(&msg);
        return ProcessResult { new_urls: vec![] };
    }

    let headers = resp.headers().clone();
    let content_type = headers
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !content_type.contains("text/html") {
        let content = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("Error reading content from {}: {}", normalized_url, e);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
        };
        if content.is_empty() {
            let msg = format!("No content downloaded from {}.", normalized_url);
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }

        // --- First: Check extension before computing MD5 ---
        let filename = headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|cd| extract_filename(cd))
            .unwrap_or_else(|| {
                // Fallback: use the last segment of the URL path.
                if let Ok(parsed) = Url::parse(&normalized_url) {
                    if let Some(segment) = parsed.path_segments().and_then(|s| s.last()) {
                        segment.to_string()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            });
        if filename.is_empty() || Path::new(&filename).extension().is_none() {
            let msg = format!(
                "File from {} does not have a valid filename (or extension); skipping saving.",
                normalized_url
            );
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }
        let ext = Path::new(&filename)
            .extension()
            .unwrap()
            .to_str()
            .unwrap_or("")
            .to_lowercase();
        if ext == "pdf"
            || ext == "xml"
            || ext == "jpg"
            || ext == "png"
            || ext == "jpeg"
            || ext == "atom"
            || ext == "webp"
            || ext == "gif"
            || ext == "vcf"
        {
            let msg = format!(
                "File from {} has a forbidden extension ({}); skipping saving.",
                normalized_url, ext
            );
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }
        // --- End: Extension Check ---

        // Now compute MD5 and perform risk analysis.
        let mut hasher = Md5::new();
        hasher.update(&content);
        let digest = hasher.finalize();
        let md5_hash = format!("{:x}", digest);
        let md5_hash_upper = md5_hash.to_uppercase();

        let (risk_level, virus_name) =
            match query_md5_online(&client, &md5_hash_upper).await {
                Ok(res) => res,
                Err(e) => (format!("Error: {}", e), "".to_string()),
            };

        let risk_msg = format!(
            "URL: {} MD5: {} Risk: {} {}",
            normalized_url, md5_hash_upper, risk_level, virus_name
        );
        let _ = log_message(&risk_msg);

        if risk_level.starts_with("Benign")
            || risk_level.starts_with("Benign (auto verdict)")
        {
            let msg = format!(
                "File from {} is considered clean; skipping collection.",
                normalized_url
            );
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }

        // Determine the host string from the URL.
        let host = if let Ok(parsed) = Url::parse(&normalized_url) {
            parsed.host_str().unwrap_or("").to_string()
        } else {
            normalized_url.clone()
        };

        // --- Build the file prefix based on which domain list(s) flagged this host ---
        let mut prefix = String::new();
        if collections.malware_domains.contains(&host) {
            prefix.push_str("MalwareDomains_");
        }
        if collections.malware_domains_mail.contains(&host) {
            prefix.push_str("MalwareDomainsMail_");
        }
        if collections.phishing_domains.contains(&host) {
            prefix.push_str("PhishingDomains_");
        }
        if collections.abuse_domains.contains(&host) {
            prefix.push_str("AbuseDomains_");
        }
        if collections.mining_domains.contains(&host) {
            prefix.push_str("MiningDomains_");
        }
        if collections.spam_domains.contains(&host) {
            prefix.push_str("SpamDomains_");
        }
        if collections.malware_sub_domains.contains(&host) {
            prefix.push_str("MalwareSubDomains_");
        }
        if collections.malware_mail_sub_domains.contains(&host) {
            prefix.push_str("MalwareSubDomainsMail_");
        }
        if collections.phishing_sub_domains.contains(&host) {
            prefix.push_str("PhishingSubDomains_");
        }
        if collections.abuse_sub_domains.contains(&host) {
            prefix.push_str("AbuseSubDomains_");
        }
        if collections.mining_sub_domains.contains(&host) {
            prefix.push_str("MiningSubDomains_");
        }
        if collections.spam_sub_domains.contains(&host) {
            prefix.push_str("SpamSubDomains_");
        }
        if !virus_name.is_empty() {
            prefix = format!("{}_{prefix}", virus_name);
        }
        // --- End Build Prefix ---

        let suggested_filename = format!("{}{}", prefix, filename);
        let file_path = zeroday_dir.join(&suggested_filename);

        match fs::write(&file_path, &content).await {
            Ok(_) => {
                let msg = format!("Downloaded and saved file: {:?}", file_path);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
            Err(e) => {
                let msg = format!("Error saving file from {}: {}", normalized_url, e);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
        }
    } else {
        // --- HTML Content Processing ---
        const MAX_DEPTH: usize = 3; // Process depth 0, 1, and 2.
        let text_content = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("Error reading HTML content from {}: {}", normalized_url, e);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
        };
        if depth >= MAX_DEPTH {
            let msg = format!(
                "HTML content from {} reached max recursion depth; skipping link extraction.",
                normalized_url
            );
            let _ = log_message(&msg);
            return ProcessResult { new_urls: vec![] };
        }
        let document = Html::parse_document(&text_content);
        let selector = Selector::parse("a[href]").unwrap();
        let base_url = match Url::parse(&normalized_url) {
            Ok(u) => u,
            Err(e) => {
                let msg = format!("Error parsing base URL {}: {}", normalized_url, e);
                let _ = log_message(&msg);
                return ProcessResult { new_urls: vec![] };
            }
        };
        let mut new_urls = Vec::new();
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(resolved) = base_url.join(href) {
                    // Enqueue only links on the same host.
                    if resolved.host_str() == base_url.host_str() {
                        new_urls.push(resolved.to_string());
                    }
                }
            }
        }
        let msg = format!(
            "HTML content from {} scanned; found {} related URLs.",
            normalized_url,
            new_urls.len()
        );
        let _ = log_message(&msg);
        return ProcessResult { new_urls };
    }
}

/// Updates the progress display on one line using a carriage return.
fn update_progress(processed: usize, total: usize) {
    print!("\rProcessed: {}/{}", processed, total);
    io::stdout().flush().unwrap();
}
async fn process_task(
    task: Task,
    client: Arc<reqwest::Client>,
    collections: Arc<DomainCollections>,
    whitelist: Arc<WhiteListCollections>,
    zeroday_dir: Arc<PathBuf>,
    processed: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    max_depth: usize,
) -> Vec<String> {
    let result = process_url(
        task.url,
        task.depth,
        client,
        collections,
        whitelist,
        zeroday_dir,
        processed,
        semaphore,
    )
    .await;
    if task.depth < max_depth {
        result.new_urls
    } else {
        vec![]
    }
}

/// Updates the progress display (using a carriage return).
fn print_progress(processed: usize, total: usize) {
    update_progress(processed, total);
}

/// Main asynchronous function.
async fn async_main() -> Result<()> {
    let script_dir = std::env::current_dir()?;
    let website_dir = script_dir.join("website");
    let zeroday_dir = Arc::new(script_dir.join("zeroday"));
    fs::create_dir_all(&*zeroday_dir).await?;
    let log_dir = script_dir.join("log");
    std::fs::create_dir_all(&log_dir)?;

    let domain_collections = Arc::new(load_domain_collections(&website_dir)?);
    let union_domains = domain_collections.union_all();
    if union_domains.is_empty() {
        let msg = "No domains found in your malware lists.";
        log_message(msg)?;
        println!("{}", msg);
        return Ok(());
    }
    let start_msg = format!("Starting scan for {} domains.", union_domains.len());
    log_message(&start_msg)?;

    let whitelist = Arc::new(load_whitelist_collections(&website_dir)?);

    let client = Arc::new(
        reqwest::Client::builder()
            .user_agent("ZeroDayMalwareCollector/1.0")
            .build()?,
    );
    let processed_set = Arc::new(Mutex::new(HashSet::new()));
    let semaphore = Arc::new(Semaphore::new(100));

    let initial_count = union_domains.len();
    let (tx0, rx0) = mpsc::unbounded_channel::<Task>();
    let (tx1, rx1) = mpsc::unbounded_channel::<Task>();

    for url in union_domains {
        tx0.send(Task { url, depth: 0 }).unwrap();
    }
    // Wrap receivers in TokioMutex so multiple workers can share them.
    let rx0 = Arc::new(TokioMutex::new(rx0));
    let rx1 = Arc::new(TokioMutex::new(rx1));

    let total_count = Arc::new(AtomicUsize::new(initial_count));
    let processed_count = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));

    // Set max_depth to 3 (process depth 0, 1, and 2)
    let max_depth = 3;
    let worker_count = 20;
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let tx1_clone = tx1.clone();
        let rx0_clone = rx0.clone();
        let rx1_clone = rx1.clone();
        let client = client.clone();
        let collections = domain_collections.clone();
        let whitelist = whitelist.clone();
        let zeroday_dir = zeroday_dir.clone();
        let processed_set = processed_set.clone();
        let semaphore = semaphore.clone();
        let total_count = total_count.clone();
        let processed_count = processed_count.clone();
        workers.push(tokio::spawn(async move {
            loop {
                // Use biased select: if a depth 1 task is available, process it first.
                let task_opt = tokio::select! {
                    biased;
                    task = async { rx1_clone.lock().await.recv().await } => task,
                    task = async { rx0_clone.lock().await.recv().await } => task,
                };
                let task = match task_opt {
                    Some(t) => t,
                    None => break,
                };
                // Capture the current depth before moving `task`
                let current_depth = task.depth;
                let new_urls = process_task(
                    task,
                    client.clone(),
                    collections.clone(),
                    whitelist.clone(),
                    zeroday_dir.clone(),
                    processed_set.clone(),
                    semaphore.clone(),
                    max_depth,
                ).await;
                processed_count.fetch_add(1, Ordering::Relaxed);
                if !new_urls.is_empty() {
                    for url in new_urls {
                        total_count.fetch_add(1, Ordering::Relaxed);
                        // Use the captured depth here instead of accessing `task.depth`
                        tx1_clone.send(Task { url, depth: current_depth + 1 }).unwrap();
                    }
                }
            }
        }));
    }
    drop(tx0);
    drop(tx1);

    let progress_thread = {
        let total_count = total_count.clone();
        let processed_count = processed_count.clone();
        let done = done.clone();
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let proc = processed_count.load(Ordering::Relaxed);
                let tot = total_count.load(Ordering::Relaxed);
                print_progress(proc, tot);
                thread::sleep(Duration::from_millis(200));
            }
            let proc = processed_count.load(Ordering::Relaxed);
            let tot = total_count.load(Ordering::Relaxed);
            print_progress(proc, tot);
            println!();
        })
    };

    join_all(workers).await;
    done.store(true, Ordering::Relaxed);
    progress_thread.join().unwrap();

    println!(
        "\nScan completed. Total URLs processed: {}",
        processed_count.load(Ordering::Relaxed)
    );
    Ok(())
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async_main()).unwrap();
        })?
        .join()
        .map_err(|e| anyhow::anyhow!("Thread panicked: {:?}", e))?;
    Ok(())
}
