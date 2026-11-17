// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::{self, PrivateKey, PublicKey};
use crate::network_info::{self, NetworkInfo};
use crate::peer::{PeerAddress, PeerEndpoint, PeerId, PrivatePeer};
use crate::utils;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
#[cfg(not(feature = "transport-quic"))]
use tracing::warn;
use tracing_subscriber::filter::LevelFilter;

pub const CONFIG_VERSION: u64 = 1;
pub const DEFAULT_PORT: u16 = 40403;
const AUTO_GENERATE_TOKEN: &str = "on:start";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("parse error")]
    Parse(#[from] toml::de::Error),
    #[error("unsupported config version {found}, expected {expected}")]
    UnsupportedVersion { found: u64, expected: u64 },
    #[error("no peer key configured")]
    MissingPeerKey,
    #[error("peer id does not match derived public key")]
    PeerIdMismatch,
    #[error("chain '{0}' is not configured")]
    MissingChain(String),
    #[error("invalid listen directive; expected false or a list of addresses")]
    InvalidListen,
    #[error("auto-generate must be set to \"{AUTO_GENERATE_TOKEN}\" when enabled")]
    InvalidAutoGenerate,
    #[error("missing genesis_short_hash for custom chain '{chain}'")]
    MissingGenesis { chain: String },
    #[error("failed to derive public key from private key")]
    PubKeyDerive(#[from] crypto::KeygenError),
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub chain: ChainRuntime,
    pub paths: ResolvedPaths,
    pub log: LogRuntime,
    pub net: NetRuntime,
    pub peer: PrivatePeer,
}

#[derive(Debug, Clone)]
pub struct ChainRuntime {
    pub name: String,
    pub db_path: PathBuf,
    pub network: NetworkInfo<'static>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    pub config_path: Option<PathBuf>,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub logs_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LogRuntime {
    pub level: Option<LevelFilter>,
    pub filters: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NetRuntime {
    pub listen_tcp: Vec<SocketAddr>,
    pub listen_quic: Vec<SocketAddr>,
    pub connect: Vec<PeerAddress>,
    pub entrypoints: EntrypointsConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntrypointsConfig {
    #[serde(default)]
    pub fixed: Vec<PeerEndpoint>,
    #[serde(default)]
    pub auto: Option<EntrypointsAuto>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntrypointsAuto {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub prefer_port: Option<u16>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(rename = "default")]
    pub default_chain: Option<String>,
    #[serde(default)]
    pub paths: Option<PathsConfig>,
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub net: Option<NetConfig>,
    #[serde(default)]
    pub peer: Option<PeerConfig>,
    #[serde(default)]
    pub chains: HashMap<String, ChainConfig>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PathsConfig {
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub logs_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub filters: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(default)]
    pub listen: Option<ListenConfig>,
    #[serde(default)]
    pub connect: Vec<PeerAddress>,
    #[serde(default)]
    pub entrypoints: EntrypointsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListenConfig {
    Flag(bool),
    One(String),
    Many(Vec<ListenEntry>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListenEntry {
    Simple(String),
    Detailed(ListenDetailed),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenDetailed {
    pub bind: String,
    #[serde(default)]
    pub transports: Option<Vec<Transport>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Quic,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PeerConfig {
    #[serde(default)]
    pub id: Option<PeerId>,
    #[serde(default)]
    pub key: Option<PrivateKey>,
    #[serde(rename = "auto-generate", default)]
    pub auto_generate: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub bootstrap_dns: Vec<String>,
    #[serde(default)]
    pub whitelist: Option<Whitelist>,
    #[serde(default)]
    pub genesis_short_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Whitelist {
    Flag(bool),
    Detailed {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        url: Option<String>,
    },
}

pub fn load_runtime(
    config_dir: Option<PathBuf>,
    chain_override: Option<String>,
    listen_override: Option<Vec<PeerAddress>>,
    connect_override: Option<Vec<PeerAddress>>,
) -> Result<RuntimeConfig, ConfigError> {
    let config_dir = preferred_config_dir(config_dir)?;
    std::fs::create_dir_all(&config_dir)?;

    let config_path = bootstrap_config(&config_dir)?;
    let config_file = load_config_file(Some(&config_path), &config_dir)?;

    let paths_cfg = config_file.paths.clone();
    let log_cfg = config_file.log.clone();
    let net_cfg = config_file.net.clone();
    let peer_cfg = config_file.peer.clone();
    let chains = config_file.chains.clone();

    let paths = resolve_paths(config_dir.clone(), Some(config_path.clone()), paths_cfg);
    ensure_dirs(&paths)?;
    let chain_name = resolve_chain_name(chain_override, &config_file)?;
    let chain_runtime = resolve_chain(&chain_name, &chains, &paths)?;
    let log_runtime = resolve_log(log_cfg);
    let net_runtime = resolve_net(net_cfg, listen_override, connect_override)?;
    let peer = resolve_peer(peer_cfg.as_ref(), &net_runtime.entrypoints)?;

    Ok(RuntimeConfig {
        chain: chain_runtime,
        paths,
        log: log_runtime,
        net: net_runtime,
        peer,
    })
}

fn preferred_config_dir(arg: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    if let Some(p) = arg {
        return Ok(expand_home(&p));
    }

    if let Ok(env) = std::env::var("HATHOR_CONFIG_DIR")
        && !env.is_empty()
    {
        return Ok(expand_home(Path::new(&env)));
    }

    if let Some(p) = utils::project_dir() {
        return Ok(p);
    }

    Ok(std::env::current_dir()?)
}

fn bootstrap_config(config_dir: &Path) -> Result<PathBuf, ConfigError> {
    let cfg_path = config_dir.join("config.toml");

    if cfg_path.exists() {
        return Ok(cfg_path);
    }

    if let Some(parent) = cfg_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (priv_key, pub_key) = crypto::gen_keypair(Default::default())?;
    let peer_id = pub_key.gen_peer_id();

    let mut default = ConfigFile::default();
    default.version = Some(CONFIG_VERSION);
    default.default_chain = Some("mainnet".to_string());
    default.net = Some(NetConfig {
        listen: Some(default_listen_config()),
        connect: Vec::new(),
        entrypoints: EntrypointsConfig::default(),
    });
    default.peer = Some(PeerConfig {
        id: Some(peer_id),
        key: Some(priv_key),
        auto_generate: None,
    });

    let serialized = toml::to_string_pretty(&default).expect("serialize default config");
    fs::write(&cfg_path, serialized)?;
    Ok(cfg_path)
}

fn ensure_dirs(paths: &ResolvedPaths) -> Result<(), ConfigError> {
    fs::create_dir_all(&paths.data_dir)?;
    fs::create_dir_all(&paths.logs_dir)?;
    Ok(())
}

fn load_config_file(path: Option<&Path>, _config_dir: &Path) -> Result<ConfigFile, ConfigError> {
    let Some(path) = path else {
        return Ok(ConfigFile::default());
    };

    match fs::read_to_string(path) {
        Ok(contents) => {
            let cfg: ConfigFile = toml::from_str(&contents)?;
            let version = cfg.version.unwrap_or(CONFIG_VERSION);
            if version != CONFIG_VERSION {
                return Err(ConfigError::UnsupportedVersion {
                    found: version,
                    expected: CONFIG_VERSION,
                });
            }
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(e.into()),
        Err(e) => Err(e.into()),
    }
}

fn resolve_paths(
    config_dir: PathBuf,
    config_path: Option<PathBuf>,
    paths: Option<PathsConfig>,
) -> ResolvedPaths {
    let base = |p: &Path| {
        if p.is_absolute() {
            return p.to_path_buf();
        }
        config_dir.join(p)
    };

    let mut data_dir = paths
        .as_ref()
        .and_then(|p| p.data_dir.clone())
        .map(|p| expand_home(&p))
        .map(|p| base(&p))
        .unwrap_or_else(|| config_dir.join("data"));

    let mut logs_dir = paths
        .as_ref()
        .and_then(|p| p.logs_dir.clone())
        .map(|p| expand_home(&p))
        .map(|p| base(&p))
        .unwrap_or_else(|| config_dir.join("logs"));

    if let Some(dir) = data_dir.parent()
        && dir == Path::new("")
    {
        data_dir = config_dir.join(data_dir);
    }

    if let Some(dir) = logs_dir.parent()
        && dir == Path::new("")
    {
        logs_dir = config_dir.join(logs_dir);
    }

    ResolvedPaths {
        config_path,
        config_dir,
        data_dir,
        logs_dir,
    }
}

fn resolve_chain_name(
    chain_override: Option<String>,
    file: &ConfigFile,
) -> Result<String, ConfigError> {
    if let Some(name) = chain_override {
        return Ok(normalize_chain_name(name));
    }
    if let Some(name) = &file.default_chain {
        return Ok(normalize_chain_name(name.clone()));
    }
    Ok("mainnet".to_string())
}

fn resolve_chain(
    name: &str,
    chains: &HashMap<String, ChainConfig>,
    paths: &ResolvedPaths,
) -> Result<ChainRuntime, ConfigError> {
    let chain_cfg = chains.get(name);
    let db_name = chain_cfg
        .and_then(|c| c.db.clone())
        .unwrap_or_else(|| format!("{name}.db"));
    let db_path = paths.data_dir.join(db_name);
    let network = build_network_info(name, chain_cfg)?;
    Ok(ChainRuntime {
        name: name.to_string(),
        db_path,
        network,
    })
}

fn build_network_info(
    name: &str,
    cfg: Option<&ChainConfig>,
) -> Result<NetworkInfo<'static>, ConfigError> {
    let default_network = default_network_info(name);

    let has_custom = cfg
        .map(|c| c.genesis_short_hash.is_some() || !c.bootstrap_dns.is_empty())
        .unwrap_or(false);
    if !has_custom && let Some(default) = default_network.clone() {
        return Ok(default);
    }

    let genesis_short_hash = cfg.and_then(|c| c.genesis_short_hash.clone()).or_else(|| {
        default_network
            .as_ref()
            .map(|n| n.genesis_short_hash.to_string())
    });

    let bootstrap = cfg
        .and_then(|c| c.bootstrap_dns.first().cloned())
        .or_else(|| {
            default_network
                .as_ref()
                .and_then(|n| n.bootstrap_txt_domain.as_ref().map(|d| d.to_string()))
        });

    let genesis_short_hash = genesis_short_hash.ok_or_else(|| ConfigError::MissingGenesis {
        chain: name.to_string(),
    })?;

    Ok(match bootstrap {
        Some(domain) => NetworkInfo::local_with_bootstrap(
            Box::leak(name.to_string().into_boxed_str()),
            Box::leak(genesis_short_hash.into_boxed_str()),
            Box::leak(domain.into_boxed_str()),
        ),
        None => NetworkInfo::local(
            Box::leak(name.to_string().into_boxed_str()),
            Box::leak(genesis_short_hash.into_boxed_str()),
        ),
    })
}

fn default_network_info(name: &str) -> Option<NetworkInfo<'static>> {
    match name {
        "mainnet" => Some(network_info::NETWORK_INFO_MAINNET.clone()),
        "testnet" | "testnet-india" => Some(network_info::NETWORK_INFO_TESTNET_INDIA.clone()),
        "testnet-golf" => Some(network_info::NETWORK_INFO_TESTNET_GOLF.clone()),
        "testnet-hotel" => Some(network_info::NETWORK_INFO_TESTNET_HOTEL.clone()),
        _ => None,
    }
}

fn resolve_log(log: Option<LogConfig>) -> LogRuntime {
    let level = log
        .as_ref()
        .and_then(|l| l.level.as_deref())
        .and_then(|lvl| lvl.parse::<LevelFilter>().ok());
    let filters = log
        .map(|l| l.filters)
        .unwrap_or_default()
        .into_iter()
        .collect();
    LogRuntime { level, filters }
}

fn resolve_net(
    net: Option<NetConfig>,
    listen_override: Option<Vec<PeerAddress>>,
    connect_override: Option<Vec<PeerAddress>>,
) -> Result<NetRuntime, ConfigError> {
    let mut net_rt = NetRuntime::default();
    let mut entrypoints = EntrypointsConfig::default();

    if let Some(cfg) = net.clone() {
        net_rt.connect = cfg.connect;
        entrypoints = cfg.entrypoints;
    }

    // Apply connect override
    if let Some(connect) = connect_override {
        net_rt.connect = connect;
    }

    // Resolve listen addresses
    if let Some(listen) = listen_override {
        let mut tcp = Vec::new();
        #[cfg(feature = "transport-quic")]
        let mut quic = Vec::new();
        for addr in listen {
            let socket = addr.to_socket_addr().ok_or(ConfigError::InvalidListen)?;
            match addr.protocol() {
                crate::peer::Protocol::Tcp => tcp.push(socket),
                #[cfg(feature = "transport-quic")]
                crate::peer::Protocol::Quic => quic.push(socket),
            }
        }
        net_rt.listen_tcp = tcp;
        #[cfg(feature = "transport-quic")]
        {
            net_rt.listen_quic = quic;
        }
    } else {
        let listen_cfg = net
            .and_then(|n| n.listen)
            .unwrap_or_else(default_listen_config);
        let listens = resolve_listen_config(listen_cfg)?;
        for l in listens {
            if l.tcp {
                net_rt.listen_tcp.push(l.bind);
            }
            if l.quic {
                net_rt.listen_quic.push(l.bind);
            }
        }
    }

    net_rt.entrypoints = entrypoints;
    Ok(net_rt)
}

fn resolve_peer(
    peer: Option<&PeerConfig>,
    entrypoints: &EntrypointsConfig,
) -> Result<PrivatePeer, ConfigError> {
    let cfg = peer.cloned().unwrap_or_default();

    if cfg.auto_generate.is_some() {
        if cfg.auto_generate.as_deref() != Some(AUTO_GENERATE_TOKEN) {
            return Err(ConfigError::InvalidAutoGenerate);
        }
        let (priv_key, pub_key) = crypto::gen_keypair(Default::default())?;
        let peer_id = pub_key.gen_peer_id();
        return Ok(PrivatePeer {
            peer_id,
            pub_key,
            priv_key,
            endpoints: entrypoints.fixed.clone(),
        });
    }

    let key = cfg.key.ok_or(ConfigError::MissingPeerKey)?;
    let pub_key: PublicKey = key.derive_pub_key()?;
    let derived_peer_id = pub_key.gen_peer_id();

    if let Some(expected_id) = cfg.id
        && expected_id != derived_peer_id
    {
        return Err(ConfigError::PeerIdMismatch);
    }

    Ok(PrivatePeer {
        peer_id: derived_peer_id,
        pub_key,
        priv_key: key,
        endpoints: entrypoints.fixed.clone(),
    })
}

#[derive(Debug, Clone)]
struct ListenRuntime {
    bind: SocketAddr,
    tcp: bool,
    quic: bool,
}

fn default_listen_config() -> ListenConfig {
    ListenConfig::Many(vec![ListenEntry::Simple(format!("[::]:{DEFAULT_PORT}"))])
}

fn resolve_listen_config(cfg: ListenConfig) -> Result<Vec<ListenRuntime>, ConfigError> {
    match cfg {
        ListenConfig::Flag(false) => Ok(Vec::new()),
        ListenConfig::Flag(true) => Err(ConfigError::InvalidListen),
        ListenConfig::One(s) => Ok(vec![parse_listen_entry(ListenEntry::Simple(s))?]),
        ListenConfig::Many(entries) => entries.into_iter().map(parse_listen_entry).collect(),
    }
}

fn parse_listen_entry(entry: ListenEntry) -> Result<ListenRuntime, ConfigError> {
    let (bind, transports) = match entry {
        ListenEntry::Simple(s) => (parse_socket(&s)?, None),
        ListenEntry::Detailed(d) => (parse_socket(&d.bind)?, d.transports),
    };

    let (mut tcp, mut quic) = default_transports();
    if let Some(ts) = transports {
        tcp = false;
        quic = false;
        for t in ts {
            match t {
                Transport::Tcp => tcp = true,
                Transport::Quic => quic = true,
            }
        }
    }

    #[cfg(not(feature = "transport-quic"))]
    if quic {
        warn!("quic requested in listen config but transport-quic feature is disabled; ignoring");
        quic = false;
    }

    Ok(ListenRuntime { bind, tcp, quic })
}

fn parse_socket(s: &str) -> Result<SocketAddr, ConfigError> {
    s.parse::<SocketAddr>()
        .map_err(|_| ConfigError::InvalidListen)
}

fn default_transports() -> (bool, bool) {
    #[cfg(feature = "transport-quic")]
    {
        (true, true)
    }
    #[cfg(not(feature = "transport-quic"))]
    {
        (true, false)
    }
}

fn expand_home(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped);
    }
    path.to_path_buf()
}

fn normalize_chain_name(name: String) -> String {
    match name.as_str() {
        "testnet" => "testnet-india".to_string(),
        _ => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_info;
    use std::str::FromStr;

    fn example_peer_id() -> PeerId {
        PeerId::from_str("c68251cd14fb3d02eb743f39c5663f291f17d40f466fc0207eae28a82cd4e0ba")
            .expect("id")
    }

    fn example_key() -> PrivateKey {
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCm7Vo0rHK6ejgDqSwv27QglSmDdEMMQ7uZJiQl/86ITDVAVx1u1l0nCqh7SHH59FUtVOdc/X9iL3jTDxNrizQU5y6CpKJe+4EdaCMzvxks9aaq+ozoumS00uFiUN7CkLWKrYZBSH2/EV9+xGjUXJBuz7B6fh8rZBq5y0QX2VrLnStGs0WGjxoRme639fPFpIGovwu48yM0olbv0NStJgsHqTCNPiRJ/K1InIBR6O3gt7T9+f3jDb1E7PKB4DsVaglF1mG0ZATNG2F5xmfDrGM113fZQ3gagenXS0NZb119ltQZPzuM6mDrD76Ura7X0y2ND/PLER0Qx0n0EV1tnMIpAgMBAAECggEADOK3mudQ9+olVssBWTRphDZffQFFh7XWzmyuT6yegdD4L15KLFsp17Cv7sxZ2ASvao9qSLhc0/R8LDa2tg+J1q893OHektxxTBbU2NLAm8LeucYbiH+S9I5uzYsWlwhaqzjX60QwSMaLi5qXyQTYNWWc5ufDejMBCSSSvhCOPLdmRg6RB5bnQJ1rh0hGTz9zqge9DQTT7PkEhjPTSXWhNaf45sYAXPq7AiLteESBJ6bXOhb5woiF8Q2zlM2r5Cl6/IEkrpg+iC1CcGVpS70UIq/8nsScYODxqZ+w6bEHwH0UzfSRgmWPaWkfmzR7qR8iBzG2VcfTW4RAyWyrpez//QKBgQDXGbYyXIXij/49BYB2XYlK+BmhfWNHX1J1Ng3VqCerBoUpO//ScXwLWKRw3ehBFEmbEfy6kXMG9Me6JeinGQIEMnx2lvwpchipHdytEZnNd68hF36evh91RPvc00/3Q5ia6MLNnmE8zh6TWBUDX2TKrj7vi5fk/OHuX9Ug2q2k1wKBgQDGqr6tV+K3TY3sQnwWwfBBmInu+e+nHXmAtXFZVMxyW9zNVt2CbOp+kpwihUJv90p7o7fX6eeawYOP+ldigThYKpJH1SYEHsDN1QNmiRC4EDqxMllCih0ANO4QYOG+GPUzhSA1G0PgGrA+mdpb8VT52lNxrVMBw3UBBCVPUUTw/wKBgQC9Id2DMLmEeioJS8Il0Z77rWUUCuV1h0pAx7Oobv/aMJR7qkcJqkFw1JNarrQeLRF/aXR4M5YZwrevZM/JxYJxYFbyC1ZTtwAaC6jTAIvlD1yM01TBjdipS2vOQnuopeYUJ5/KHn3PckmOMz/exE0irc2m4W5AqV6bM+Z5ye4u5wKBgA8xd6uiEQCbucLbwsmqw0kA9WuFScKqCmTBe42tYoVMaTJ69i3HTpendrFdJ5uQee3Cs4ibps67Bei46H3sC/cSKmW781BVWcFkDQKGcPTiqNpsU083aMhfQ+WUwy7akcYC5FerYiF9aQUglwZ5ClqhS8hhzPtRi10sh/3s5SzZAoGAb7VAybRoq5Q6xPxtNE3mV3aeryS0t2D6PUlJ9JK6NYOpMISrZOphgVN5ylVKRdu9+AebI4AUBkgboMhYIuRi9+t7+ZiqFIgNZovjNlNfxpW9gPdc2NlkoUVEnsYPSkaBkg4TcuDj67aU8GR3rQy+0kwawrjNtgPfrFRym1Cqdf0="
            .parse()
            .expect("key")
    }

    #[test]
    fn peer_inline_round_trip() {
        let entrypoints = EntrypointsConfig::default();
        let cfg = PeerConfig {
            id: Some(example_peer_id()),
            key: Some(example_key()),
            auto_generate: None,
        };
        let peer = resolve_peer(Some(&cfg), &entrypoints).expect("peer");
        assert_eq!(peer.peer_id, example_peer_id());
    }

    #[test]
    fn peer_id_mismatch() {
        let entrypoints = EntrypointsConfig::default();
        let mut cfg = PeerConfig {
            id: Some(
                PeerId::from_str(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
            key: Some(example_key()),
            auto_generate: None,
        };
        let res = resolve_peer(Some(&cfg), &entrypoints);
        assert!(matches!(res, Err(ConfigError::PeerIdMismatch)));

        cfg.id = None;
        let res = resolve_peer(Some(&cfg), &entrypoints);
        assert!(res.is_ok());
    }

    #[test]
    fn peer_auto_generate_requires_token() {
        let entrypoints = EntrypointsConfig::default();
        let cfg = PeerConfig {
            id: None,
            key: None,
            auto_generate: Some("maybe".to_string()),
        };
        let res = resolve_peer(Some(&cfg), &entrypoints);
        assert!(matches!(res, Err(ConfigError::InvalidAutoGenerate)));
    }

    #[test]
    fn listen_bool_false_parses() {
        let cfg = NetConfig {
            listen: Some(ListenConfig::Flag(false)),
            connect: Vec::new(),
            entrypoints: EntrypointsConfig::default(),
        };
        let net = resolve_net(Some(cfg), None, None).expect("net");
        assert!(net.listen_tcp.is_empty());
        assert!(net.listen_quic.is_empty());
    }

    #[test]
    fn chain_normalizes_testnet_alias() {
        let cfg = ConfigFile::default();
        let name = resolve_chain_name(Some("testnet".to_string()), &cfg).expect("chain");
        assert_eq!(name, "testnet-india");
    }

    #[test]
    fn default_network_info_used_for_mainnet() {
        let net = build_network_info("mainnet", None).expect("net");
        assert_eq!(net, network_info::NETWORK_INFO_MAINNET.clone());
    }

    #[test]
    fn listen_override_preserves_connect_from_config() {
        let cfg = NetConfig {
            listen: Some(ListenConfig::Many(vec![ListenEntry::Simple(
                "127.0.0.1:8001".into(),
            )])),
            connect: vec!["tcp://127.0.0.1:9000/".parse().unwrap()],
            entrypoints: EntrypointsConfig::default(),
        };

        let net = resolve_net(
            Some(cfg),
            Some(vec!["tcp://127.0.0.1:8002/".parse().unwrap()]),
            None,
        )
        .expect("net");
        assert_eq!(net.connect.len(), 1);
        assert_eq!(net.connect[0].to_string(), "tcp://127.0.0.1:9000/");
        assert_eq!(net.listen_tcp.len(), 1);
        assert_eq!(net.listen_tcp[0].to_string(), "127.0.0.1:8002");
    }
}
