use clap::{App, Arg, ArgGroup};
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("jector")
        .version("1.0")
        .author("Lewis Clark")
        .group(
            ArgGroup::with_name("target")
                .arg("pid")
                .arg("window")
                .required(true),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .value_name("pid")
                .help("The PID of the process to inject into")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("window")
                .short("w")
                .long("window")
                .value_name("window_name")
                .help("The name of the window to inject into")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("dll_file_path")
                .help("The DLL file to inject")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("method")
                .short("m")
                .long("method")
                .value_name("loadlibrary/manualmap")
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

    let method = matches.value_of("method").unwrap().parse()?;

    if let Some(pid) = matches.value_of("pid") {
        jector::inject_pid(pid.parse()?, &file_bytes, method)?;
    } else if let Some(window_name) = matches.value_of("window") {
        jector::inject_window(window_name, &file_bytes, method)?;
    } else {
        panic!("Expected either -p or -w arg");
    };

    Ok(())
}
