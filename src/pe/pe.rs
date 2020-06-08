use std::fs::File;
use std::io::Read;
use crate::winapiwrapper::dosheader::DosHeader;
use crate::winapiwrapper::coffheader::CoffHeader;

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

	pub fn dos_header(&self) -> DosHeader {
		DosHeader::from_ptr(self.image.as_ptr())
	}

	pub fn coff_header(&self) -> CoffHeader {
		let pe_offset = self.dos_header().e_lfanew();
		let coff_offset = self.image.as_ptr() as usize + pe_offset as usize + 0x4;
		// + 0x4 to offset past the pe signature

		CoffHeader::from_ptr(coff_offset as *const u8)
	}
}
