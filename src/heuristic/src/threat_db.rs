use std::ptr;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

const MAX_SIGNATURES: usize = 50000;
const MAX_SIGNATURE_LENGTH: usize = 512;
const HASH_SIZE: usize = 32;

#[repr(C)]
pub struct SignatureEntry {
    pub name: [u8; 128],
    pub signature: [u8; MAX_SIGNATURE_LENGTH],
    pub sig_length: i32,
    pub threat_type: i32,
    pub severity: i32,
    pub malware_family: [u8; 64],
}

#[repr(C)]
pub struct ThreatInfo {
    pub threat_id: [u8; 64],
    pub name: [u8; 128],
    pub threat_type: [u8; 64],
    pub family: [u8; 128],
    pub severity: i32,
    pub confidence: f32,
    pub description: [u8; 1024],
}

#[repr(C)]
pub struct DatabaseStats {
    pub total_signatures: i32,
    pub families_count: i32,
    pub last_update: i64,
    pub version: [u8; 32],
}

struct ThreatDatabase {
    signatures: HashMap<String, SignatureEntry>,
    malware_families: HashMap<String, Vec<String>>,
    statistics: DatabaseStats,
}

impl ThreatDatabase {
    fn new() -> Self {
        ThreatDatabase {
            signatures: HashMap::new(),
            malware_families: HashMap::new(),
            statistics: DatabaseStats {
                total_signatures: 0,
                families_count: 0,
                last_update: 0,
                version: [0; 32],
            },
        }
    }

    fn add_signature(&mut self, name: &str, sig: &[u8], threat_type: i32, severity: i32, family: &str) {
        let mut entry = SignatureEntry {
            name: [0u8; 128],
            signature: [0u8; MAX_SIGNATURE_LENGTH],
            sig_length: sig.len() as i32,
            threat_type,
            severity,
            malware_family: [0u8; 64],
        };

        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(127);
        entry.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let sig_len = sig.len().min(MAX_SIGNATURE_LENGTH);
        entry.signature[..sig_len].copy_from_slice(&sig[..sig_len]);

        let family_bytes = family.as_bytes();
        let family_len = family_bytes.len().min(63);
        entry.malware_family[..family_len].copy_from_slice(&family_bytes[..family_len]);

        self.signatures.insert(name.to_string(), entry);

        if !family.is_empty() && family != "Unknown" {
            let family_list = self.malware_families.entry(family.to_string()).or_insert_with(Vec::new);
            if !family_list.contains(&name.to_string()) {
                family_list.push(name.to_string());
            }
        }

        self.statistics.total_signatures = self.signatures.len() as i32;
        self.statistics.families_count = self.malware_families.len() as i32;
        self.statistics.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
    }

    fn find_signature(&self, data: &[u8]) -> Option<(String, &SignatureEntry)> {
        for (name, entry) in &self.signatures {
            let sig_len = entry.sig_length as usize;
            if sig_len <= data.len() {
                if data[..sig_len].iter().zip(entry.signature.iter()).all(|(a, b)| a == b) {
                    return Some((name.clone(), entry));
                }
            }
        }
        None
    }

    fn get_statistics(&self) -> DatabaseStats {
        self.statistics
    }

    fn search_by_family(&self, family: &str) -> Vec<&SignatureEntry> {
        if let Some(members) = self.malware_families.get(family) {
            members.iter()
                .filter_map(|name| self.signatures.get(name))
                .collect()
        } else {
            Vec::new()
        }
    }
}

static mut DATABASE: Option<ThreatDatabase> = None;

fn get_db() -> &'static mut ThreatDatabase {
    unsafe {
        if DATABASE.is_none() {
            DATABASE = Some(ThreatDatabase::new());
        }
        DATABASE.as_mut().unwrap()
    }
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

fn analyze_pe_header(data: &[u8]) -> (bool, bool, f32) {
    if data.len() < 64 { return (false, false, 0.0); }

    let dos_sig = u16::from_le_bytes([data[0], data[1]]);
    if dos_sig != 0x5A4D { return (false, false, 0.0); }

    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 24 > data.len() { return (false, false, 0.0); }

    let pe_sig = u32::from_le_bytes([data[e_lfanew], data[e_lfanew + 1], data[e_lfanew + 2], data[e_lfanew + 3]]);
    if pe_sig != 0x00004550 { return (false, false, 0.0); }

    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
    let sections_offset = e_lfanew + 24 + optional_header_size as usize;

    let mut total_entropy = 0.0f32;
    let mut section_count = 0;
    let mut has_packed_section = false;
    let suspicious_names = [b".upx", b".aspack", b".petite", b".themida", b".vmp", b"packed", b"stub"];

    for i in 0..num_sections.min(10) {
        let sec_offset = sections_offset + i * 40;
        if sec_offset + 40 > data.len() { break; }

        let raw_size = u32::from_le_bytes([data[sec_offset + 16], data[sec_offset + 17], data[sec_offset + 18], data[sec_offset + 19]]);
        if raw_size == 0 { continue; }

        let start = u32::from_le_bytes([data[sec_offset + 20], data[sec_offset + 21], data[sec_offset + 22], data[sec_offset + 23]]) as usize;

        if start + (raw_size as usize).min(1024 * 1024) <= data.len() {
            let end = (start + (raw_size as usize).min(1024 * 1024)).min(data.len());
            let section_data = &data[start..end];
            let entropy = calculate_entropy(section_data);
            total_entropy += entropy;

            if entropy > 7.0 { has_packed_section = true; }
        }

        let name_bytes = &data[sec_offset..sec_offset + 8];
        for susp in suspicious_names.iter() {
            if name_bytes.windows(susp.len()).any(|w| w == *susp) {
                has_packed_section = true;
            }
        }

        section_count += 1;
    }

    let avg_entropy = if section_count > 0 { total_entropy / section_count as f32 } else { 0.0 };
    (avg_entropy > 6.5, has_packed_section, avg_entropy)
}

fn check_suspicious_patterns(data: &[u8]) -> i32 {
    let patterns = [
        b"VirtualAlloc", b"VirtualProtect", b"CreateRemoteThread",
        b"WriteProcessMemory", b"LoadLibrary", b"GetProcAddress",
        b"WinExec", b"ShellExecute", b"URLDownload", b"InternetOpen",
        b"CreateProcess", b"ExitProcess", b"GetModuleHandle",
        b"SetWindowsHookEx", b"UnhookWindowsHookEx", b"FindWindow",
        b"SetWindowsHookEx", b"CreateRemoteThread", b"OpenProcess",
    ];

    let mut count = 0;
    for pattern in patterns.iter() {
        if data.windows(pattern.len()).any(|w| w == *pattern) {
            count += 1;
        }
    }
    count.min(20)
}

#[no_mangle]
pub extern "C" fn init_threat_db(db_path: *const libc::c_char) -> i32 {
    if db_path.is_null() { return 0; }
    let db = get_db();
    db.statistics = DatabaseStats {
        total_signatures: 0,
        families_count: 0,
        last_update: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        version: [0; 32],
    };
    let version_str = b"1.0.0";
    db.statistics.version[..version_str.len()].copy_from_slice(version_str);
    1
}

#[no_mangle]
pub extern "C" fn close_threat_db() {
    unsafe {
        DATABASE = None;
    }
}

#[no_mangle]
pub extern "C" fn add_signature(name: *const libc::c_char, sig: *const u8, sig_len: i32, threat_type: i32, severity: i32, family: *const libc::c_char) -> i32 {
    if name.is_null() || sig.is_null() || sig_len <= 0 { return 0; }

    let name_str = unsafe { CStr::from_ptr(name).to_string_lossy().into_owned() };
    let signature = unsafe { std::slice::from_raw_parts(sig, sig_len as usize).to_vec() };
    let family_str = if family.is_null() { "Unknown".to_string() } else { unsafe { CStr::from_ptr(family).to_string_lossy().into_owned() } };

    let db = get_db();
    db.add_signature(&name_str, &signature, threat_type, severity, &family_str);
    1
}

#[no_mangle]
pub extern "C" fn analyze_threat(filepath: *const libc::c_char) -> ThreatInfo {
    let mut info = ThreatInfo {
        threat_id: [0u8; 64],
        name: [0u8; 128],
        threat_type: [0u8; 64],
        family: [0u8; 128],
        severity: 0,
        confidence: 0.0,
        description: [0u8; 1024],
    };

    if filepath.is_null() { return info; }

    let path = unsafe { CStr::from_ptr(filepath).to_string_lossy() };
    let mut file = match File::open(path.as_ref()) {
        Ok(f) => f,
        Err(_) => return info,
    };

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok();

    if buffer.len() > 10 * 1024 * 1024 {
        buffer.truncate(10 * 1024 * 1024);
    }

    let (is_packed, has_suspicious, entropy) = analyze_pe_header(&buffer);
    let suspicious_count = check_suspicious_patterns(&buffer);

    let mut score = 0.0f32;
    if is_packed { score += 30.0; }
    if has_suspicious { score += 25.0; }
    if entropy > 7.0 { score += 20.0; }
    if suspicious_count >= 3 { score += (suspicious_count as f32) * 5.0; }

    if score > 100.0 { score = 100.0; }

    if score > 50.0 {
        let threat_name = if is_packed && has_suspicious { "Packed.Obfuscated.Malware" }
                        else if is_packed { "Packed.Executable" }
                        else if suspicious_count >= 5 { "Suspicious.Process" }
                        else { "Potential.Threat" };

        let name_bytes = threat_name.as_bytes();
        let copy_len = name_bytes.len().min(127);
        info.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let type_bytes = b"Trojan";
        info.threat_type[..type_bytes.len()].copy_from_slice(type_bytes);

        let family_bytes = b"Unknown";
        info.family[..family_bytes.len()].copy_from_slice(family_bytes);

        info.severity = if score > 80.0 { 5 } else if score > 60.0 { 4 } else if score > 40.0 { 3 } else { 2 };
        info.confidence = score / 100.0;

        let desc = format!("score:{:.1},packed:{},suspicious:{},entropy:{:.2}", score, is_packed, suspicious_count, entropy);
        let desc_bytes = desc.as_bytes();
        let copy_len = desc_bytes.len().min(1023);
        info.description[..copy_len].copy_from_slice(&desc_bytes[..copy_len]);
    }

    info
}

#[no_mangle]
pub extern "C" fn quick_threat_check(filepath: *const libc::c_char) -> i32 {
    if filepath.is_null() { return 0; }

    let path = unsafe { CStr::from_ptr(filepath).to_string_lossy() };
    let mut file = match File::open(path.as_ref()) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let mut header = [0u8; 8192];
    let n = file.read(&mut header).unwrap_or(0);
    if n < 512 { return 0; }

    let (is_packed, _, entropy) = analyze_pe_header(&header[..n]);
    if entropy > 6.5 || is_packed { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn get_database_stats() -> DatabaseStats {
    let db = get_db();
    db.get_statistics()
}

#[no_mangle]
pub extern "C" fn get_db_version() -> *const libc::c_char {
    b"1.0.0\0".as_ptr() as *const libc::c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_database_initialization() {
        unsafe {
            init_threat_db(ptr::null());
            assert!(DATABASE.is_some());
        }
    }
}