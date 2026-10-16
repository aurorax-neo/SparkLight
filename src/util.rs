use std::{path::Path, process::Command};
use anyhow::{Context, Result, bail};

pub fn launch_brave(target_url: Option<&str>) -> Result<()> {
    let brave_path = Path::new("/Applications/Brave Browser.app");
    if !brave_path.exists() {
        bail!("未在系统中找到 Brave 浏览器: /Applications/Brave Browser.app");
    }

    let url = target_url.unwrap_or("https://www.douyin.com");

    let status = Command::new("open")
        .args(["-a", "/Applications/Brave Browser.app", url])
        .status()
        .context("执行 open 命令启动 Brave 浏览器失败")?;

    if !status.success() {
        bail!("open 命令退出码异常: {:?}", status.code());
    }

    Ok(())
}
