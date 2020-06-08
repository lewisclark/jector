use std::fs::File;
use std::io::Read;

#[derive(Debug)]
pub struct Pe {
	image: Vec<u8>
}

impl Pe {
	pub fn from_file(file: &mut File) -> Self {
		let mut image = Vec::new();
		file.read_to_end(&mut image);

		Pe {
			image
		}
	}

	pub fn dos_header(&self) {

	}

	pub fn nt_header(&self) {

	}
}
