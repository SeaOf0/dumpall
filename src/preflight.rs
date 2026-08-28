use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub current_user: Option<String>,
    pub privilege: String,
    pub cpu_cores: usize,
    pub timezone: String,
}

pub fn run_preflight() -> PreflightReport {
    let current_user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok();
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let privilege = infer_privilege(current_user.as_deref());
    let cpu_cores = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);
    let timezone = time::UtcOffset::current_local_offset()
        .map(|offset| offset.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    PreflightReport {
        hostname,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        current_user,
        privilege,
        cpu_cores,
        timezone,
    }
}

fn infer_privilege(_current_user: Option<&str>) -> String {
    #[cfg(unix)]
    {
        // 环境变量 USER 可由调用方伪造；geteuid 是内核返回的真实有效 UID。
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        if unsafe { geteuid() } == 0 {
            return "root".to_string();
        }
    }

    #[cfg(windows)]
    {
        // USERNAME 环境变量可伪造且无法覆盖管理员组内的其他账户名；
        // CheckTokenMembership(BUILTIN\Administrators) 检查的是当前进程令牌
        // 是否真正启用了管理员 SID（UAC 提权令牌判定）。
        if windows_token_is_admin() {
            return "administrator (elevated token)".to_string();
        }
    }

    "user_or_unknown".to_string()
}

/// 检查当前进程令牌是否属于并启用 BUILTIN\Administrators（S-1-5-32-544）。
#[cfg(windows)]
fn windows_token_is_admin() -> bool {
    use windows_sys::Win32::Foundation::PSID;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SECURITY_NT_AUTHORITY,
    };
    // SECURITY_BUILTIN_DOMAIN_RID = 32, DOMAIN_ALIAS_RID_ADMINS = 544
    // （常量本体位于未启用的 SystemServices feature，按公开 RID 值字面使用）。
    let authority = SECURITY_NT_AUTHORITY;
    let mut sid: PSID = std::ptr::null_mut();
    let allocated = unsafe {
        AllocateAndInitializeSid(
            &authority,
            2,
            32,
            544,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        )
    };
    if allocated == 0 {
        return false;
    }
    let mut is_member: i32 = 0;
    // windows-sys 0.52 的 HANDLE 是 isize,null 句柄传 0。
    let checked = unsafe { CheckTokenMembership(0, sid, &mut is_member) };
    unsafe { FreeSid(sid) };
    checked != 0 && is_member != 0
}
