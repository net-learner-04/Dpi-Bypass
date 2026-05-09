mod config;
mod detect;
mod forge;
mod injector;
mod parser;
use config::Iptables;
use std::{io, process};

fn main() -> io::Result<()> {
    config::root_check();

    let rule = Iptables::new(
        Some("filter".to_string()),
        "-I".to_string(),
        "OUTPUT".to_string(),
        vec![
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            "443".to_string(),
        ],
        "NFQUEUE".to_string(),
        vec!["--queue-num".to_string(), "0".to_string()],
    );

    rule.apply()?;

    ctrlc::set_handler(|| {
        process::exit(0);
    })
    .unwrap();

    detect::start_control()?;

    Ok(())
}
