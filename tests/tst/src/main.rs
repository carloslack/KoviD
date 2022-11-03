// Rust code that can work as
// an alternative to C/bash ones in test/
//
// Pretty random, just a bunch of utilities
// in the same place
// work in progress...

use anyhow::Context;
use std::convert::From;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{self, Command},
    {thread, time},
};
use structopt::StructOpt;

const ABOUT: &str = "Random test/utility tools for KoviD";
const KVTMP: &str = "/tmp/kv";

// Convert each argument in order and
// avoid repeating OsStr::new()
macro_rules! osstr_params {
    ($($a:expr), *) => {
        &[
            $(<dyn AsRef<OsStr>>::as_ref(&$a),)*
        ]
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = ABOUT,
)]
enum CliCmd {
    #[structopt(about = "Run option")]
    Do(Do),
    #[structopt(about = "Show do options")]
    Options,
}

#[derive(Debug, StructOpt)]
struct Do {
    option: String,
}

fn fetch_output(output: &Vec<u8>) -> String {
    let mut output = String::from_utf8_lossy(&output).into_owned();
    output.truncate(output.trim_end().len());
    output
}

fn run_command(option: &str, path: &Path, args: &[&OsStr]) -> Vec<u8> {
    println!("{:?} {:?}", option, args);
    let output = Command::new(option)
        .args(args)
        .current_dir(path)
        .output()
        .unwrap_or_else(|e| panic!("{option} failed to execute process: {e}"));
    assert!(output.status.success());
    output.stdout
}

fn busy() -> ! {
    let mut val = 0;
    let mut f;
    let pid: PathBuf = PathBuf::from(format!("{}", process::id()));
    let fname: PathBuf = [Path::new(KVTMP), &pid].iter().collect();
    let d = Path::new(KVTMP);

    fs::create_dir_all(d).expect("Error creating directory {d}");
    f = File::create(fname).expect("Error creating {fname}");

    println!("{:?}", f);
    loop {
        let v = format!("{0}\n", val);
        thread::sleep(time::Duration::from_secs(1));
        f.write_all(v.as_bytes()).expect("Error writing {fname}");
        val += 1;
    }
}

fn certs() -> anyhow::Result<()> {
    let p = Path::new("certs");
    let c = osstr_params!["-p", p];
    let res = run_command("mkdir", Path::new("."), c);
    let res = fetch_output(&res);
    println!("{res}");

    let c = osstr_params![
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "server.key",
        "-x509",
        "-days",
        "30",
        "-out",
        "server.crt",
        "-subj",
        "/C=US/ST=Arizona/L=Supai Village/O=Global Security/OU=IT Department/CN=supai.com"
    ];
    let res = run_command("openssl", p, c);
    println!("{:?}", res);

    let s_key = fs::read_to_string("./certs/server.key")?;
    let s_crt = fs::read_to_string("./certs/server.crt")?;

    let mut s_pem = File::options()
        .create_new(true)
        .append(true)
        .open("certs/server.pem")?;

    s_pem.write_all(s_key.as_bytes())?;
    s_pem.write_all(s_crt.as_bytes())?;

    let c = osstr_params![
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        "key.pem",
        "-out",
        "cert.pem",
        "-days",
        "365",
        "-nodes",
        "-subj",
        "/C=US/ST=Arizona/L=Supai Village/O=Global Security/OU=IT Department/CN=supai.com"
    ];
    let res = run_command("openssl", p, c);
    println!("{:?}", res);

    Ok(())
}

fn run(opts: Do) -> anyhow::Result<()> {
    match opts.option.as_ref() {
        "busy" => busy(),
        "certs" => {
            certs().with_context(|| format!("Error generating certificates"))?;
        }
        "fork" => todo!(),
        _ => println!("Invalid command {}", opts.option),
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match CliCmd::from_args() {
        CliCmd::Options => {
            println!("busy\ncerts\nfork");
            Ok(())
        }
        CliCmd::Do(opts) => run(opts),
    }
}
