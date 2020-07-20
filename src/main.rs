use std::env;
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        let help = format!(
            "{} <pid> <dll path> <method>\n\nAvailable methods:\n{}",
            args[0], "manualmap\nloadlibrary",
        );

        println!("{}", help);
        Ok(())
    } else {
        let pid: u32 = args[1].parse()?;
        let mut dll_bytes = Vec::new();
        File::open(&args[2])?.read_to_end(&mut dll_bytes)?;
        let method = args[3].parse()?;

        jector::inject_pid(pid, &dll_bytes, method)
    }
}
