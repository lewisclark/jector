use clap::{App, Arg};
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("jector")
        .version("1.0")
        .author("Lewis Clark")
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .value_name("PID")
                .help("The PID of the process to inject into")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("DLL FILE")
                .help("The DLL file to inject")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("method")
                .short("m")
                .long("method")
                .value_name("LOADLIBRARY/MANUALMAP")
                .help("The injection method to use")
                .takes_value(true)
                .default_value("loadlibrary"),
        )
        .get_matches();

    let file_bytes = {
        let mut buf = Vec::new();
        File::open(matches.value_of("file").unwrap())?.read_to_end(&mut buf)?;

        buf
    };

    let pid = matches.value_of("pid").expect("No PID given").parse()?;
    let method = matches.value_of("method").unwrap().parse()?;

    jector::inject_pid(pid, &file_bytes, method)?;

    Ok(())
}
