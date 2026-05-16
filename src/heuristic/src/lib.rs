use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::ffi::CStr;
use std::os::raw::c_char;

const PE_HEADER_SIGNATURE: u32 = 0x00004550;
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

#[repr(C)]
pub struct HeuristicResult {
    pub score: f32,
    pub category: i32,
    pub details: [c_char; 512],
}

#[repr(C)]
pub struct PEAnalysis {
    pub is_packed: bool,
    pub is_obfuscated: bool,
    pub suspicious_imports: i32,
    pub section_count: i32,
    pub entry_point_rva: u32,
    pub entropy: f32,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f32;
    let mut entropy = 0.0f32;
    for &count in &freq {
        if count == 0 { continue; }
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn analyze_pe_sections(data: &[u8]) -> (f32, bool, bool) {
    if data.len() < 64 { return (0.0, false, false); }
    let dos_sig = read_u16(data, 0);
    if dos_sig != IMAGE_DOS_SIGNATURE { return (0.0, false, false); }
    let e_lfanew = read_u32(data, 60);
    if e_lfanew as usize + 24 > data.len() { return (0.0, false, false); }
    let pe_sig = read_u32(data, e_lfanew as usize);
    if pe_sig != PE_HEADER_SIGNATURE { return (0.0, false, false); }
    let num_sections = read_u16(data, e_lfanew as usize + 6);
    let optional_header_size = read_u16(data, e_lfanew as usize + 20);
    let sections_offset = e_lfanew as usize + 24 + optional_header_size as usize;
    let mut total_entropy = 0.0f32;
    let mut section_count = 0;
    let suspicious_names = [b".upx", b".aspack", b".petite", b".themida", b".vmp", b"packed", b"stub"];
    let mut has_suspicious_name = false;
    let mut has_high_entropy = false;
    for i in 0..num_sections.min(10) {
        let sec_offset = sections_offset + i * 40;
        if sec_offset + 40 > data.len() { break; }
        let virt_size = read_u32(data, sec_offset + 8);
        let raw_size = read_u32(data, sec_offset + 16);
        if raw_size == 0 { continue; }
        section_count += 1;
        let start = read_u32(data, sec_offset + 20) as usize;
        let size = raw_size as usize;
        if start + size <= data.len() {
            let section_data = &data[start..start + size.min(1024 * 1024)];
            let entropy = calculate_entropy(section_data);
            total_entropy += entropy;
            if entropy > 7.0 { has_high_entropy = true; }
        }
        let name_start = sec_offset;
        let name_bytes = &data[name_start..name_start + 8];
        for susp in suspicious_names.iter() {
            if name_bytes.windows(susp.len()).any(|w| w == *susp) {
                has_suspicious_name = true;
            }
        }
    }
    let avg_entropy = if section_count > 0 { total_entropy / section_count as f32 } else { 0.0 };
    let is_packed = has_high_entropy || (avg_entropy > 6.5 && section_count > 1);
    (avg_entropy, is_packed, has_suspicious_name)
}

fn check_suspicious_imports(data: &[u8]) -> i32 {
    if data.len() < 64 { return 0; }
    let e_lfanew = read_u32(data, 60) as usize;
    if e_lfanew + 24 > data.len() { return 0; }
    let optional_header_size = read_u32(data, e_lfanew + 20) as usize;
    let data_dirs_offset = e_lfanew + 24;
    let import_rva = read_u32(data, data_dirs_offset + 8) as usize;
    let mut suspicious = 0;
    let suspicious_funcs = [
        b"VirtualAlloc", b"VirtualProtect", b"CreateRemoteThread",
        b"WriteProcessMemory", b"LoadLibrary", b"GetProcAddress",
        b"WinExec", b"ShellExecute", b"URLDownload", b"InternetOpen",
    ];
    for func in suspicious_funcs.iter() {
        if data.windows(func.len()).any(|w| w == *func) {
            suspicious += 1;
        }
    }
    suspicious.min(10)
}

#[no_mangle]
pub extern "C" fn analyze_file(filepath: *const c_char) -> HeuristicResult {
    let mut result = HeuristicResult {
        score: 0.0,
        category: 0,
        details: [0; 512],
    };
    if filepath.is_null() { return result; }
    let path = unsafe { CStr::from_ptr(filepath) }.to_string_lossy();
    let path = Path::new(&path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return result,
    };
    let mut buffer = Vec::new();
    let mut small_buffer = [0u8; 65536];
    let _ = file.read(&mut small_buffer);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.read_to_end(&mut buffer);
    let buffer = if buffer.len() > 10 * 1024 * 1024 {
        buffer[..10 * 1024 * 1024].to_vec()
    } else { buffer };
    let (entropy, is_packed, has_suspicious_name) = analyze_pe_sections(&buffer);
    let suspicious_imports = check_suspicious_imports(&buffer);
    let mut score = 0.0f32;
    if is_packed { score += 30.0; }
    if has_suspicious_name { score += 25.0; }
    if entropy > 7.0 { score += 20.0; }
    if suspicious_imports >= 3 { score += (suspicious_imports as f32) * 5.0; }
    if score > 100.0 { score = 100.0; }
    result.score = score;
    if is_packed && has_suspicious_name { result.category = 2; }
    else if is_packed || suspicious_imports >= 3 { result.category = 1; }
    else { result.category = 0; }
    let details = format!(
        "entropy:{:.2},packed:{},suspicious_name:{},imports:{}",
        entropy, is_packed, has_suspicious_name, suspicious_imports
    );
    let details_bytes = details.as_bytes();
    let copy_len = details_bytes.len().min(511);
    for (i, &b) in details_bytes[..copy_len].iter().enumerate() {
        result.details[i] = b as c_char;
    }
    result
}

#[no_mangle]
pub extern "C" fn quick_heuristic_check(filepath: *const c_char) -> i32 {
    if filepath.is_null() { return 0; }
    let path = unsafe { CStr::from_ptr(filepath) }.to_string_lossy();
    let path = Path::new(&path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut header = [0u8; 4096];
    let n = file.read(&mut header).unwrap_or(0);
    if n < 512 { return 0; }
    let (entropy, is_packed, _) = analyze_pe_sections(&header[..n]);
    if entropy > 6.5 || is_packed { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn get_module_version() -> *const c_char {
    b"1.0.0\0".as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}