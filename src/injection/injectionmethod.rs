use std::str::FromStr;

pub enum InjectionMethod {
    ManualMap,
    LoadLibrary,
}

impl FromStr for InjectionMethod {
    type Err = anyhow::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str.to_ascii_lowercase().trim() {
            "manualmap" => Ok(InjectionMethod::ManualMap),
            "loadlibrary" => Ok(InjectionMethod::LoadLibrary),
            _ => Err(anyhow!("Unknown injection method: {}", str)),
        }
    }
}
