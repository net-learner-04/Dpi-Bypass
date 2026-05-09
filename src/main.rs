mod config;
mod detect;
mod forge;
mod injector;
mod parser;
use config::Iptables;
use std::{io, process};
use std::sync::Arc;

fn main() -> io::Result<()> {
    config::root_check();

    let rule = Arc::new(Iptables::new(
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
    ));

    rule.apply()?;
    
    let rule_clone = Arc::clone(&rule);

    ctrlc::set_handler(move || {
        rule_clone.iptables_remove().ok();
        process::exit(0);
    }).unwrap();

    detect::start_control()?;

    Ok(())
}
