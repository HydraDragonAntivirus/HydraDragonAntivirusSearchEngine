use anyhow::Result;
use chrono::Local;
use futures::future::join_all;
use md5::{Digest, Md5};
use reqwest::{StatusCode, Url, Client};
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

/// Appends an unknown IP address to the appropriate file.
/// IPv4 addresses are saved to "IPv4Unknown.txt" while IPv6 addresses are saved to "IPv6Unknown.txt".
fn append_unknown_ip(ip: &str) -> std::io::Result<()> {
    // Decide on the filename based on IP type.
    // (Change the file names if you prefer different naming.)
    let unknown_filename = if ip.parse::<IpAddr>()
        .map(|ip| ip.is_ipv4())
        .unwrap_or(true)
    {
        "IPv4SuspiciousUnknownZeroDay.txt"
    } else {
        "IPv6SuspiciousUnknownZeroday.txt"
    };

    // Open (or create) the file in append mode.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(unknown_filename)?;
    writeln!(file, "{}", ip)?;
    Ok(())
}

/// Holds the malware IP lists loaded from files.
pub struct IpCollections {
    ipv4_malware: HashSet<String>,
    ipv6_malware: HashSet<String>,
}

impl IpCollections {
    /// Returns a union of both IPv4 and IPv6 malware IPs.
    pub fn union_all(&self) -> HashSet<String> {
        let mut union = HashSet::new();
        union.extend(self.ipv4_malware.iter().cloned());
        union.extend(self.ipv6_malware.iter().cloned());
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

/// Loads the malware IP lists from the given website directory.
fn load_ip_collections(website_dir: &Path) -> Result<IpCollections> {
    Ok(IpCollections {
        ipv4_malware: load_lines(&website_dir.join("IPv4Malware.txt"))?,
        ipv6_malware: load_lines(&website_dir.join("IPv6Malware.txt"))?,
    })
}

/// Holds the whitelist sets loaded from files.
pub struct WhiteListCollections {
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
pub struct ProcessResult {
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
async fn query_md5_online(client: &Client, md5: &str) -> Result<(String, String)> {
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

/// --- process_url function ---
/// This function downloads a URL and then either:
///   - If the content is HTML, it extracts new URLs (from <a href="..."> links)
///     that are not whitelisted. Only URLs whose hosts are valid IP addresses are kept.
///   - Otherwise, it calculates the file’s MD5 hash,
///     queries an online risk analysis service, and (if malicious) saves the file.
///     Additionally, if the risk level is "Unknown", the IP address is logged to a file
///     (but only once, so duplicates are not created).
/// The returned `ProcessResult` includes any new URLs found.
pub async fn process_url(
    url: String,
    depth: usize,
    client: Arc<Client>,
    whitelist: Arc<WhiteListCollections>,
    zeroday_dir: Arc<PathBuf>,
    processed: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    unknown_ips: Arc<Mutex<HashSet<String>>>,
) -> ProcessResult {
    // Acquire the semaphore and log the URL being processed.
    let _permit = semaphore.acquire().await.unwrap();
    let _ = log_message(&format!("Processing URL (depth {}): {}", depth, url));

    {
        // Skip if the URL was already processed.
        let mut processed_lock = processed.lock().unwrap();
        if processed_lock.contains(&url) {
            return ProcessResult { new_urls: vec![] };
        }
        processed_lock.insert(url.clone());
    }

    let normalized_url = normalize_url(&url);
    let host = match Url::parse(&normalized_url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|s| s.to_lowercase()))
    {
        Some(h) => h,
        None => {
            let _ = log_message(&format!("Failed to parse URL: {}", normalized_url));
            return ProcessResult { new_urls: vec![] };
        }
    };

    // Only process URLs whose host is a valid IP address.
    if host.parse::<IpAddr>().is_err() {
        let _ = log_message(&format!("Skipping non-IP host: {}", host));
        return ProcessResult { new_urls: vec![] };
    }

    // Also skip if the host is whitelisted.
    if is_whitelisted(&host, &whitelist) {
        let _ = log_message(&format!("Skipping whitelisted host: {}", host));
        return ProcessResult { new_urls: vec![] };
    }

    // Download the URL.
    let resp = match client
        .get(&normalized_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let _ = log_message(&format!("Error downloading {}: {}", normalized_url, e));
            return ProcessResult { new_urls: vec![] };
        }
    };

    if resp.status() != StatusCode::OK {
        let _ = log_message(&format!(
            "Failed to download {} (status: {})",
            normalized_url,
            resp.status()
        ));
        return ProcessResult { new_urls: vec![] };
    }

    let headers = resp.headers().clone();
    let content_type = headers
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Read the response content as bytes.
    let content = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            let _ = log_message(&format!("Error reading content from {}: {}", normalized_url, e));
            return ProcessResult { new_urls: vec![] };
        }
    };

    if content.is_empty() {
        let _ = log_message(&format!("No content downloaded from {}", normalized_url));
        return ProcessResult { new_urls: vec![] };
    }

    // ----------------------------------
    // HTML Branch: Extract new URLs
    // ----------------------------------
    if content_type.contains("text/html") {
        // Parse the HTML document.
        let document = Html::parse_document(&String::from_utf8_lossy(&content));

        // Create a selector for <a href="..."> elements.
        let selector = match Selector::parse("a[href]") {
            Ok(sel) => sel,
            Err(e) => {
                let _ = log_message(&format!("Error creating HTML selector: {}", e));
                return ProcessResult { new_urls: vec![] };
            }
        };

        // Get a base URL from the normalized URL.
        let base_url = match Url::parse(&normalized_url) {
            Ok(url) => url,
            Err(e) => {
                let _ = log_message(&format!("Error parsing base URL {}: {}", normalized_url, e));
                return ProcessResult { new_urls: vec![] };
            }
        };

        // Only keep new URLs whose hosts are valid IP addresses.
        let mut new_urls = Vec::new();
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(resolved) = base_url.join(href) {
                    if let Some(resolved_host) = resolved.host_str() {
                        if resolved_host.parse::<IpAddr>().is_ok() && !is_whitelisted(resolved_host, &whitelist) {
                            new_urls.push(resolved.to_string());
                        }
                    }
                }
            }
        }

        let count = new_urls.len();
        let _ = log_message(&format!(
            "Extracted {} new IP URL(s) from HTML document: {}",
            count, normalized_url
        ));

        return ProcessResult { new_urls };
    }

    // ----------------------------------
    // Non-HTML Branch: Process file
    // ----------------------------------
    // Determine the filename from the Content-Disposition header or the URL path.
    let mut filename = String::new();
    if let Some(cd) = headers.get("content-disposition").and_then(|v| v.to_str().ok()) {
        filename = extract_filename(cd).unwrap_or_default();
    }
    if filename.is_empty() {
        if let Ok(parsed) = Url::parse(&normalized_url) {
            if let Some(segment) = parsed.path_segments().and_then(|s| s.last()) {
                filename = segment.to_string();
            }
        }
    }
    if filename.is_empty() {
        let _ = log_message(&format!("Unable to determine filename for {}. Skipping.", normalized_url));
        return ProcessResult { new_urls: vec![] };
    }

    // Calculate the MD5 hash of the file content.
    let mut hasher = Md5::new();
    hasher.update(&content);
    let digest = hasher.finalize();
    let md5_hash = format!("{:x}", digest).to_uppercase();

    // Query the online MD5 risk analysis service.
    let (risk_level, virus_name) = match query_md5_online(&client, &md5_hash).await {
        Ok(result) => result,
        Err(e) => {
            let _ = log_message(&format!("Error querying MD5 for {}: {}", normalized_url, e));
            return ProcessResult { new_urls: vec![] };
        }
    };
    let _ = log_message(&format!(
        "URL: {} MD5: {} Risk: {} Virus: {}",
        normalized_url, md5_hash, risk_level, virus_name
    ));

    // Skip if the file is considered clean.
    if risk_level.starts_with("Benign (auto verdict)") {
        let _ = log_message(&format!("File from {} is considered clean by auto verdict; skipping.", normalized_url));
        return ProcessResult { new_urls: vec![] };
    }

    if risk_level.starts_with("Benign") {
        let _ = log_message(&format!("File from {} is considered clean; skipping.", normalized_url));
        return ProcessResult { new_urls: vec![] };
    }

    // --- NEW: If the risk level is unknown, log the IP address to file (only once) ---
    if risk_level.to_lowercase().starts_with("unknown") {
        // Use the shared unknown_ips set to avoid duplicates.
        let mut unknown_lock = unknown_ips.lock().unwrap();
        if !unknown_lock.contains(&host) {
            unknown_lock.insert(host.clone());
            if let Err(e) = append_unknown_ip(&host) {
                let _ = log_message(&format!("Failed to save unknown IP {}: {}", host, e));
            } else {
                let _ = log_message(&format!("Logged unknown IP: {}", host));
            }
        }
        return ProcessResult { new_urls: vec![] };
    }

    // Save the file (for Malware or Suspicious risk levels).
    let file_path = zeroday_dir.join(&filename);
    match fs::write(&file_path, &content).await {
        Ok(_) => {
            let _ = log_message(&format!("Downloaded and saved file: {:?}", file_path));
        }
        Err(e) => {
            let _ = log_message(&format!("Error saving file from {}: {}", normalized_url, e));
        }
    }

    // For non-HTML files no new URLs are extracted.
    ProcessResult { new_urls: vec![] }
}

/// Updates the progress display on one line using a carriage return.
fn update_progress(processed: usize, total: usize) {
    print!("\rProcessed: {}/{}", processed, total);
    io::stdout().flush().unwrap();
}

async fn process_task(
    task: Task,
    client: Arc<Client>,
    whitelist: Arc<WhiteListCollections>,
    zeroday_dir: Arc<PathBuf>,
    processed: Arc<Mutex<HashSet<String>>>,
    semaphore: Arc<Semaphore>,
    max_depth: usize,
    unknown_ips: Arc<Mutex<HashSet<String>>>,
) -> Vec<String> {
    let result = process_url(
        task.url,
        task.depth,
        client,
        whitelist,
        zeroday_dir,
        processed,
        semaphore,
        unknown_ips,
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

    // Load only the IP malware lists.
    let ip_collections = Arc::new(load_ip_collections(&website_dir)?);
    let union_ips = ip_collections.union_all();
    if union_ips.is_empty() {
        let msg = "No IP addresses found in your malware lists.";
        log_message(msg)?;
        println!("{}", msg);
        return Ok(());
    }
    let start_msg = format!("Starting scan for {} IP addresses.", union_ips.len());
    log_message(&start_msg)?;

    let whitelist = Arc::new(load_whitelist_collections(&website_dir)?);

    let client = Arc::new(
        Client::builder()
            .user_agent("ZeroDayMalwareCollector/1.0")
            .build()?,
    );
    let processed_set = Arc::new(Mutex::new(HashSet::new()));
    // Create a shared set for unknown IP addresses to avoid duplicates.
    let unknown_ips = Arc::new(Mutex::new(HashSet::new()));
    let semaphore = Arc::new(Semaphore::new(100));

    let initial_count = union_ips.len();
    let (tx0, rx0) = mpsc::unbounded_channel::<Task>();
    let (tx1, rx1) = mpsc::unbounded_channel::<Task>();

    // Enqueue each IP address as an initial task.
    for ip in union_ips {
        tx0.send(Task { url: ip, depth: 0 }).unwrap();
    }
    // Wrap receivers in TokioMutex so multiple workers can share them.
    let rx0 = Arc::new(TokioMutex::new(rx0));
    let rx1 = Arc::new(TokioMutex::new(rx1));

    let total_count = Arc::new(AtomicUsize::new(initial_count));
    let processed_count = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));

    // Set max_depth to 10 (process depth 0 to 10)
    let max_depth = 10;
    let worker_count = 50;
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let tx1_clone = tx1.clone();
        let rx0_clone = rx0.clone();
        let rx1_clone = rx1.clone();
        let client = client.clone();
        let whitelist = whitelist.clone();
        let zeroday_dir = zeroday_dir.clone();
        let processed_set = processed_set.clone();
        let semaphore = semaphore.clone();
        let total_count = total_count.clone();
        let processed_count = processed_count.clone();
        let unknown_ips = unknown_ips.clone();
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
                let current_depth = task.depth;
                let new_urls = process_task(
                    task,
                    client.clone(),
                    whitelist.clone(),
                    zeroday_dir.clone(),
                    processed_set.clone(),
                    semaphore.clone(),
                    max_depth,
                    unknown_ips.clone(),
                ).await;
                processed_count.fetch_add(1, Ordering::Relaxed);
                if !new_urls.is_empty() {
                    for url in new_urls {
                        total_count.fetch_add(1, Ordering::Relaxed);
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
