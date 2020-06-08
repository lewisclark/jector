use std::env;
use std::error;

mod config;

use config::Config;

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args();
    println!("args: {:?}", args);

    let config = Config::from_args(&mut args);
    println!("config: {:?}", config?);

    Ok(())
}
