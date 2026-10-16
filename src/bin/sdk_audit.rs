//! 显式维护命令，与主服务、账号数据库、调度器完全分离。
use anyhow::{Context, Result, ensure};
use sparklight::douyin::{
    sdk_registry::{MAX_RESOURCE_SIZE, SdkRegistry, ValidatedManifest},
    sdk_runtime::probe_source,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).context("无法读取资源文件")?;
    ensure!(file.metadata()?.is_file(), "资源必须为普通文件");
    let mut data = Vec::new();
    file.take(max + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= max, "资源超过上限");
    Ok(data)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3 && ["check", "probe", "fetch", "activate"].contains(&args[0].as_str()),
        "用法: sdk_audit <check|probe|fetch|activate> <manifest.json> <resource-directory>"
    );
    let manifest = ValidatedManifest::parse(&read_bounded(Path::new(&args[1]), 1024 * 1024)?)?;
    let dir = PathBuf::from(&args[2]);
    if args[0] == "fetch" {
        // 只允许全新目录，避免替换既有基准；不携带 Cookie、不允许重定向/代理。
        std::fs::create_dir(&dir).context("下载目录必须尚不存在；保留已验证资源")?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(45))
            .build()?;
        for (name, url, size) in manifest.resource_sources() {
            let mut response = client.get(url).send().await.context("公开资源下载失败")?;
            ensure!(
                response.status().is_success(),
                "公开资源 HTTP 状态异常，停止"
            );
            ensure!(
                response
                    .content_length()
                    .is_none_or(|n| n <= MAX_RESOURCE_SIZE),
                "公开资源过大"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len() + chunk.len() <= size as usize
                        && bytes.len() + chunk.len() <= MAX_RESOURCE_SIZE as usize,
                    "资源大小发生变化，拒绝保存"
                );
                bytes.extend_from_slice(&chunk);
            }
            let meta = manifest.verify_resource(name, &bytes)?;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            println!("{} {} {}", meta.name(), meta.size(), meta.sha256());
        }
        return Ok(());
    }
    // 读取同一不可变字节快照；不在通过校验后重新打开执行可变文件。
    let data: Vec<_> = manifest
        .resource_sources()
        .map(|(name, _, size)| Ok((name.to_owned(), read_bounded(&dir.join(name), size)?)))
        .collect::<Result<_>>()?;
    let refs: Vec<_> = data
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let candidate = manifest.verify_candidate(&refs)?;
    let mut registry = SdkRegistry::new();
    if args[0] == "activate" {
        registry.activate_candidate(&candidate)?;
    }
    for meta in candidate.resources() {
        if args[0] == "probe" {
            let source = &data
                .iter()
                .find(|(name, _)| name == meta.name())
                .context("资源快照缺失")?
                .1;
            println!(
                "{} {}",
                meta.name(),
                serde_json::to_string(&probe_source(source, meta.sha256())?)?
            );
        } else {
            println!("{} {} {}", meta.name(), meta.size(), meta.sha256());
        }
    }
    println!(
        "当前生产版本：{}；资源一致性不等于适配器获批",
        registry.current_release().id()
    );
    Ok(())
}
