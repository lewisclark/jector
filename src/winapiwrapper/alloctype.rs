use winapi::um::winnt;

bitflags! {
	pub struct AllocType: u32 {
		const MEM_COMMIT = winnt::MEM_COMMIT;
		const MEM_RESERVE = winnt::MEM_RESERVE;
		const MEM_RESET = winnt::MEM_RESET;
		const MEM_RESET_UNDO = winnt::MEM_RESET_UNDO;
	}
}
