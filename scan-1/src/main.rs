use std::fs;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::net::TcpStream;
use std::io::{Write, stdout};

fn perform_nmap_scan(target_hostname: &str, scan_type: &str) -> Result<(String, String, String), String> {
    let scan_args = format!("nmap -p 1-65535 {} {}", scan_type, target_hostname);
    let result = std::process::Command::new("sh")
        .arg("-c")
        .arg(&scan_args)
        .output()
        .map_err(|e| format!("Error executing Nmap: {}", e))?;

    Ok((
        target_hostname.to_string(),
        scan_type.to_string(),
        String::from_utf8_lossy(&result.stdout).to_string(),
    ))
}

fn save_progress(index: u32) -> Result<(), std::io::Error> {
    fs::write("progress.txt", index.to_string())
}

fn load_progress() -> u32 {
    match fs::read_to_string("progress.txt") {
        Ok(content) => content.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

fn is_internet_available() -> bool {
    TcpStream::connect("www.google.com:80").is_ok()
}

fn main() {
    println!("Starting the script...");

    let all_results: Arc<Mutex<Vec<(String, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let start_i = load_progress();

    while !is_internet_available() {
        println!("Waiting for internet connection...");
        thread::sleep(Duration::from_secs(10));
    }

    let total_tasks = 99 * 100;

    let (tx, rx) = mpsc::channel();

    for i in start_i..100 {
        for j in 1..100 {
            let hostname = format!("e2e-{:02}-{:02}.ssdcloudindia.net", i, j);
            let scan_types: Vec<String> = vec![" -A -T4".to_string()];
            for scan_type in scan_types.iter() {
                let tx = tx.clone();
                let all_results_clone = Arc::clone(&all_results);
                let hostname_clone = hostname.clone(); // Clone the hostname for each iteration
                let scan_type_clone = scan_type.clone(); // Clone the scan_type for each iteration
                thread::spawn(move || {
                    println!("Scanning {}...", hostname_clone);
                    let result = perform_nmap_scan(&hostname_clone, &scan_type_clone);
                    tx.send(result.clone()).unwrap();

                    let mut results = all_results_clone.lock().unwrap();
                    results.push(result.unwrap());
                });
            }

            save_progress(i + 1).unwrap();
        }
    }

    drop(tx);

    let mut summary_file = fs::File::create("report.txt").expect("Error creating report.txt");

    for (idx, result) in rx.iter().enumerate() {
        let (hostname, scan_type, scan_result) = result.unwrap();
        summary_file.write_all(format!("Scan Type: {}\nHostname: {}\n{}\n", scan_type, hostname, scan_result).as_bytes())
            .expect("Error writing to report.txt");
        
        let progress = ((idx + 1) as f64 / total_tasks as f64) * 100.0;
        print!("\rProgress: {:.2}%", progress);
        stdout().flush().unwrap();
    }

    println!("\nScript completed.");
}
