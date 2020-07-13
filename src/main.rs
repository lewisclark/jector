#[macro_use]
extern crate bitflags;

use std::env;
use std::fs::File;
use std::io::Read;

mod error;
mod injector;
mod winapiwrapper;

use error::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        return Err(Box::new(Error::new(format!(
            "{} <pid> <dll path>",
            args[0]
        ))));
    }

    let pid: u32 = args[1].parse()?;
    let mut dll_bytes = Vec::new();
    File::open(&args[2])?.read_to_end(&mut dll_bytes)?;

    jector::inject_pid(pid, &dll_bytes)
}
