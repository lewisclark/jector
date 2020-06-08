use std::fs::File;
use std::io::Read;
use std::ptr;
use crate::winapiwrapper::dosheader::DosHeader;

type Image = Vec<u8>;

#[derive(Debug)]
pub struct Pe {
	image: Image
}

impl Pe {
	pub fn from_file(file: &mut File) -> Self {
		let mut image = Vec::new();
		file.read_to_end(&mut image);

		Pe {
			image
		}
	}

	pub fn dos_header(&self) -> DosHeader {
		DosHeader::from_ptr(self.image.as_ptr())
	}

	/*
	pub fn pe_header(&self) -> PeHeader {
		let pe_offset = self.dos_header().e_lfanew();
		let address = (self.image.as_ptr() as usize) + pe_offset;

		unsafe {
			ptr::read(address as *const u8)
		}
	}
	*/
}
