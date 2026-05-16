use std::ptr;
use std::ffi::CStr;
use std::collections::HashMap;

const MAX_RULES: usize = 10000;
const MAX_PATH_LEN: usize = 1024;

#[repr(C)]
pub struct BehaviorRule {
    pub rule_id: i32,
    pub name: [u8; 128],
    pub description: [u8; 512],
    pub category: [u8; 64],
    pub severity: i32,
    pub enabled: i32,
}

#[repr(C)]
pub struct BehaviorEvent {
    pub timestamp: i64,
    pub event_type: [u8; 64],
    pub process_name: [u8; 260],
    pub process_path: [u8; MAX_PATH_LEN],
    pub target_path: [u8; MAX_PATH_LEN],
    pub action: [u8; 128],
    pub result: i32,
    pub severity: i32,
}

#[repr(C)]
pub struct BehaviorStatistics {
    pub total_events: i64,
    pub blocked_actions: i64,
    pub allowed_actions: i64,
    pub alerts_generated: i64,
    pub rules_count: i32,
}

struct BehaviorMonitor {
    rules: HashMap<i32, BehaviorRule>,
    events: Vec<BehaviorEvent>,
    statistics: BehaviorStatistics,
}

impl BehaviorMonitor {
    fn new() -> Self {
        BehaviorMonitor {
            rules: HashMap::new(),
            events: Vec::new(),
            statistics: BehaviorStatistics {
                total_events: 0,
                blocked_actions: 0,
                allowed_actions: 0,
                alerts_generated: 0,
                rules_count: 0,
            },
        }
    }

    fn add_rule(&mut self, rule_id: i32, name: &str, description: &str, category: &str, severity: i32) {
        let mut rule = BehaviorRule {
            rule_id,
            name: [0u8; 128],
            description: [0u8; 512],
            category: [0; 64],
            severity,
            enabled: 1,
        };

        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(127);
        rule.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let desc_bytes = description.as_bytes();
        let desc_len = desc_bytes.len().min(511);
        rule.description[..desc_len].copy_from_slice(&desc_bytes[..desc_len]);

        let cat_bytes = category.as_bytes();
        let cat_len = cat_bytes.len().min(63);
        rule.category[..cat_len].copy_from_slice(&cat_bytes[..cat_len]);

        self.rules.insert(rule_id, rule);
        self.statistics.rules_count = self.rules.len() as i32;
    }

    fn log_event(&mut self, event_type: &str, process_name: &str, process_path: &str, target_path: &str, action: &str, severity: i32) {
        let mut event = BehaviorEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            event_type: [0; 64],
            process_name: [0; 260],
            process_path: [0; MAX_PATH_LEN],
            target_path: [0; MAX_PATH_LEN],
            action: [0; 128],
            result: 0,
            severity,
        };

        let event_type_bytes = event_type.as_bytes();
        let copy_len = event_type_bytes.len().min(63);
        event.event_type[..copy_len].copy_from_slice(&event_type_bytes[..copy_len]);

        let proc_name_bytes = process_name.as_bytes();
        let proc_name_len = proc_name_bytes.len().min(259);
        event.process_name[..proc_name_len].copy_from_slice(&proc_name_bytes[..proc_name_len]);

        let proc_path_bytes = process_path.as_bytes();
        let proc_path_len = proc_path_bytes.len().min(MAX_PATH_LEN - 1);
        event.process_path[..proc_path_len].copy_from_slice(&proc_path_bytes[..proc_path_len]);

        let target_bytes = target_path.as_bytes();
        let target_len = target_bytes.len().min(MAX_PATH_LEN - 1);
        event.target_path[..target_len].copy_from_slice(&target_bytes[..target_len]);

        let action_bytes = action.as_bytes();
        let action_len = action_bytes.len().min(127);
        event.action[..action_len].copy_from_slice(&action_bytes[..action_len]);

        self.events.push(event);
        self.statistics.total_events += 1;

        if severity >= 3 {
            self.statistics.alerts_generated += 1;
        }
    }

    fn block_action(&mut self) {
        self.statistics.blocked_actions += 1;
    }

    fn allow_action(&mut self) {
        self.statistics.allowed_actions += 1;
    }

    fn get_statistics(&self) -> BehaviorStatistics {
        self.statistics
    }

    fn get_recent_events(&self, count: usize) -> Vec<&BehaviorEvent> {
        self.events.iter().rev().take(count).collect()
    }
}

static mut MONITOR: Option<BehaviorMonitor> = None;

fn get_monitor() -> &'static mut BehaviorMonitor {
    unsafe {
        if MONITOR.is_none() {
            MONITOR = Some(BehaviorMonitor::new());
            let m = MONITOR.as_mut().unwrap();
            m.add_rule(1, "Registry Modification", "Monitors registry changes", "Registry", 3);
            m.add_rule(2, "File Encryption", "Detects file encryption activity", "FileSystem", 5);
            m.add_rule(3, "Process Injection", "Monitors for process injection", "Process", 5);
            m.add_rule(4, "Network Connection", "Monitors network connections", "Network", 2);
            m.add_rule(5, "Autorun Modification", "Monitors autorun entries", "Startup", 4);
        }
        MONITOR.as_mut().unwrap()
    }
}

#[no_mangle]
pub extern "C" fn init_behavior_monitor() -> i32 {
    get_monitor();
    1
}

#[no_mangle]
pub extern "C" fn close_behavior_monitor() {
    unsafe {
        MONITOR = None;
    }
}

#[no_mangle]
pub extern "C" fn add_behavior_rule(rule_id: i32, name: *const libc::c_char, description: *const libc::c_char, category: *const libc::c_char, severity: i32) -> i32 {
    if name.is_null() { return 0; }

    let name_str = unsafe { CStr::from_ptr(name).to_string_lossy().into_owned() };
    let desc_str = if description.is_null() { String::new() } else { unsafe { CStr::from_ptr(description).to_string_lossy().into_owned() } };
    let cat_str = if category.is_null() { String::new() } else { unsafe { CStr::from_ptr(category).to_string_lossy().into_owned() } };

    get_monitor().add_rule(rule_id, &name_str, &desc_str, &cat_str, severity);
    1
}

#[no_mangle]
pub extern "C" fn log_behavior_event(event_type: *const libc::c_char, process_name: *const libc::c_char, process_path: *const libc::c_char, target_path: *const libc::c_char, action: *const libc::c_char, severity: i32) -> i32 {
    if event_type.is_null() || process_name.is_null() { return 0; }

    let event_str = unsafe { CStr::from_ptr(event_type).to_string_lossy().into_owned() };
    let proc_str = unsafe { CStr::from_ptr(process_name).to_string_lossy().into_owned() };
    let proc_path_str = if process_path.is_null() { String::new() } else { unsafe { CStr::from_ptr(process_path).to_string_lossy().into_owned() } };
    let target_str = if target_path.is_null() { String::new() } else { unsafe { CStr::from_ptr(target_path).to_string_lossy().into_owned() } };
    let action_str = if action.is_null() { String::new() } else { unsafe { CStr::from_ptr(action).to_string_lossy().into_owned() } };

    get_monitor().log_event(&event_str, &proc_str, &proc_path_str, &target_str, &action_str, severity);
    1
}

#[no_mangle]
pub extern "C" fn block_behavior() -> i32 {
    get_monitor().block_action();
    1
}

#[no_mangle]
pub extern "C" fn allow_behavior() -> i32 {
    get_monitor().allow_action();
    1
}

#[no_mangle]
pub extern "C" fn get_behavior_stats() -> BehaviorStatistics {
    get_monitor().get_statistics()
}

#[no_mangle]
pub extern "C" fn get_recent_behavior_events(count: i32) -> i32 {
    let events = get_monitor().get_recent_events(count as usize);
    events.len() as i32
}

#[no_mangle]
pub extern "C" fn check_suspicious_behavior(process_name: *const libc::c_char) -> i32 {
    if process_name.is_null() { return 0; }

    let name = unsafe { CStr::from_ptr(process_name).to_string_lossy().into_owned() };

    let suspicious_patterns = [
        "powershell", "cmd.exe", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32", "certutil",
    ];

    for pattern in suspicious_patterns.iter() {
        if name.to_lowercase().contains(pattern) {
            return 1;
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn get_monitor_version() -> *const libc::c_char {
    b"1.0.0\0".as_ptr() as *const libc::c_char
}