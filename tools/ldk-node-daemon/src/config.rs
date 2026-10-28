use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use electrum_client::ElectrumApi;
use ldk_node::bitcoin::{blockdata::constants::genesis_block, Network};
use ldk_node::chicory::JitServiceConfig;
use ldk_node::{Builder, Node};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	pub network: String,
	pub data_dir: PathBuf,
	pub listen_address: String,
	pub alias: String,
	pub chain_source: ChainSource,
	#[serde(default)]
	pub chicory: ChicoryPolicy,
}

// No Debug implementation: the Core variant holds a password.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChainSource {
	Bitcoind { host: String, port: u16, user: String, password: String },
	Electrum { url: String },
	Esplora { url: String },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChicoryPolicy {
	pub enabled: bool,
	#[serde(default = "default_flat_fee")]
	pub flat_fee_sat: u64,
	#[serde(default = "default_ppm")]
	pub fee_ppm: u32,
	#[serde(default = "default_client_cap")]
	pub max_client_funding_sats: u64,
	#[serde(default = "default_total_cap")]
	pub max_total_fronted_sats: u64,
}
impl Default for ChicoryPolicy {
	fn default() -> Self {
		Self {
			enabled: false,
			flat_fee_sat: default_flat_fee(),
			fee_ppm: default_ppm(),
			max_client_funding_sats: default_client_cap(),
			max_total_fronted_sats: default_total_cap(),
		}
	}
}
fn default_flat_fee() -> u64 {
	100
}
fn default_ppm() -> u32 {
	1000
}
fn default_client_cap() -> u64 {
	500_000
}
fn default_total_cap() -> u64 {
	2_000_000
}

pub fn network(name: &str) -> Result<Network, String> {
	match name {
		"bitcoin" => Ok(Network::Bitcoin),
		"testnet" => Ok(Network::Testnet),
		"signet" => Ok(Network::Signet),
		"regtest" => Ok(Network::Regtest),
		_ => Err("Choose bitcoin, testnet, signet or regtest explicitly".into()),
	}
}

pub fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
	let file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW)
		.open(path)
		.map_err(|_| "Cannot open private regular file".to_owned())?;
	let metadata = file.metadata().map_err(|_| "Cannot inspect private file")?;
	if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > maximum
	{
		return Err("Private file must be regular, bounded, and inaccessible to other users".into());
	}
	let mut bytes = Vec::new();
	file.take(maximum + 1).read_to_end(&mut bytes).map_err(|_| "Cannot read private file")?;
	if bytes.len() as u64 > maximum {
		return Err("Private file is too large".into());
	}
	Ok(bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
	let temp = path.with_extension("pending");
	// The parent is a private directory under an exclusively held process lock.
	let mut file = OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(&temp)
		.map_err(|_| "Cannot create durable state file")?;
	file.set_permissions(fs::Permissions::from_mode(0o600))
		.map_err(|_| "Cannot protect state file")?;
	file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|_| "Cannot persist state file")?;
	fs::rename(&temp, path).map_err(|_| "Cannot replace durable state file")?;
	File::open(path.parent().ok_or("Missing state directory")?)
		.and_then(|dir| dir.sync_all())
		.map_err(|_| "Cannot persist state directory")?;
	Ok(())
}

impl Config {
	pub fn read(path: &Path) -> Result<Self, String> {
		let config: Self = serde_json::from_slice(&read_private(path, MAX_CONFIG_BYTES)?)
			.map_err(|_| "Invalid daemon configuration")?;
		config.validate()?;
		Ok(config)
	}

	pub fn validate(&self) -> Result<(), String> {
		network(&self.network)?;
		if !self.data_dir.is_absolute()
			|| self.alias.is_empty()
			|| self.alias.len() > 32
			|| self.alias.chars().any(char::is_control)
		{
			return Err(
				"Use an absolute data directory and a printable alias of at most 32 bytes".into()
			);
		}
		let address: SocketAddr = self
			.listen_address
			.parse()
			.map_err(|_| "Listen address must be a literal IP and port")?;
		if address.port() == 0 {
			return Err("Listen port must be nonzero".into());
		}
		self.policy().validate().map_err(|_| "Invalid provider fees or funding limits")?;
		match &self.chain_source {
			ChainSource::Bitcoind { host, port, user, password } => {
				if host.is_empty()
					|| host.len() > 253
					|| host.contains(['/', '@', '\\', '?', '#'])
					|| *port == 0 || user.is_empty()
					|| password.is_empty()
				{
					return Err("Invalid Bitcoin Core connection configuration".into());
				}
			},
			ChainSource::Electrum { url } => {
				let parsed = reqwest::Url::parse(url).map_err(|_| "Invalid Electrum URL")?;
				if !["tcp", "ssl"].contains(&parsed.scheme())
					|| parsed.host_str().is_none()
					|| parsed.port().is_none()
					|| !parsed.username().is_empty()
					|| parsed.password().is_some()
					|| parsed.query().is_some()
					|| parsed.fragment().is_some()
				{
					return Err("Use tcp://host:port or ssl://host:port for Electrum".into());
				}
			},
			ChainSource::Esplora { url } => {
				let parsed = reqwest::Url::parse(url).map_err(|_| "Invalid Esplora URL")?;
				if !["http", "https"].contains(&parsed.scheme())
					|| parsed.host_str().is_none()
					|| !parsed.username().is_empty()
					|| parsed.password().is_some()
					|| parsed.query().is_some()
					|| parsed.fragment().is_some()
				{
					return Err(
						"Use an HTTP(S) Esplora base URL without embedded credentials".into()
					);
				}
			},
		}
		Ok(())
	}

	pub fn policy(&self) -> JitServiceConfig {
		JitServiceConfig {
			enabled: self.chicory.enabled,
			relay_enabled: self.chicory.enabled,
			allow_confirmed_v2: self.chicory.enabled,
			allow_splice_jit: self.chicory.enabled,
			reuse_funding_key_on_splice: self.chicory.enabled,
			inbound_splice_minimum_depth: 6,
			flat_fee_sat: self.chicory.flat_fee_sat,
			fee_ppm: self.chicory.fee_ppm,
			max_client_funding_sats: self.chicory.max_client_funding_sats,
			max_total_fronted_sats: self.chicory.max_total_fronted_sats,
			..JitServiceConfig::default()
		}
	}

	pub fn lock_directory(&self) -> Result<File, String> {
		fs::DirBuilder::new()
			.recursive(true)
			.mode(0o700)
			.create(&self.data_dir)
			.map_err(|_| "Cannot create node directory")?;
		let metadata =
			fs::symlink_metadata(&self.data_dir).map_err(|_| "Cannot inspect node directory")?;
		if !metadata.is_dir()
			|| metadata.file_type().is_symlink()
			|| metadata.permissions().mode() & 0o077 != 0
		{
			return Err("Node directory must be private and must not be a symlink".into());
		}
		let lock = OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW)
			.open(self.data_dir.join("daemon.lock"))
			.map_err(|_| "Cannot open node lock")?;
		if !lock.metadata().map_err(|_| "Cannot inspect node lock")?.is_file() {
			return Err("Invalid node lock".into());
		}
		lock.try_lock().map_err(|_| "This node directory is already in use")?;
		let identity = self.data_dir.join("daemon-network.json");
		if identity.exists() {
			let saved: Value = serde_json::from_slice(&read_private(&identity, MAX_CONFIG_BYTES)?)
				.map_err(|_| "Invalid network binding")?;
			if saved != json!({"version": 1, "network": self.network}) {
				return Err("Node directory belongs to a different network".into());
			}
		} else {
			// Refuse to silently repurpose a pre-existing native node store.
			if fs::read_dir(&self.data_dir)
				.map_err(|_| "Cannot inspect node directory")?
				.any(|entry| entry.map_or(true, |entry| entry.file_name() != "daemon.lock"))
			{
				return Err("Existing node state has no daemon network binding; explicit migration is required".into());
			}
			atomic_write(
				&identity,
				&serde_json::to_vec(&json!({"version":1,"network":self.network}))
					.map_err(|_| "Cannot encode network binding")?,
			)?;
		}
		Ok(lock)
	}

	pub fn verify_chain(&self) -> Result<(), String> {
		let expected = genesis_block(network(&self.network)?).block_hash().to_string();
		let actual = match &self.chain_source {
			ChainSource::Electrum { url } => {
				let options =
					electrum_client::ConfigBuilder::new().timeout(Some(10)).retry(0).build();
				let client = electrum_client::Client::from_config(url, options)
					.map_err(|_| "Cannot connect to Electrum for network verification")?;
				client
					.block_header(0)
					.map_err(|_| "Cannot verify Electrum genesis")?
					.block_hash()
					.to_string()
			},
			source => {
				let client = reqwest::blocking::Client::builder()
					.timeout(Duration::from_secs(15))
					.redirect(reqwest::redirect::Policy::none())
					.build()
					.map_err(|_| "Cannot create chain verification client")?;
				match source {
					ChainSource::Bitcoind { host, port, user, password } => {
						let host = match host.parse::<IpAddr>() {
							Ok(IpAddr::V6(_)) => format!("[{host}]"),
							_ => host.clone(),
						};
						let response = client
							.post(format!("http://{host}:{port}/"))
							.basic_auth(user, Some(password))
							.json(
								&json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]}),
							)
							.send()
							.and_then(|r| r.error_for_status())
							.map_err(|_| "Cannot verify Bitcoin Core genesis")?;
						let mut bytes = Vec::new();
						response
							.take(MAX_CONFIG_BYTES + 1)
							.read_to_end(&mut bytes)
							.map_err(|_| "Cannot read chain verification response")?;
						if bytes.len() as u64 > MAX_CONFIG_BYTES {
							return Err("Oversized chain verification response".into());
						}
						let response: Value = serde_json::from_slice(&bytes)
							.map_err(|_| "Invalid chain verification response")?;
						if !response["error"].is_null() {
							return Err("Bitcoin Core refused genesis verification".into());
						}
						response["result"].as_str().ok_or("Missing genesis hash")?.to_owned()
					},
					ChainSource::Esplora { url } => {
						let response = client
							.get(format!("{}/block-height/0", url.trim_end_matches('/')))
							.send()
							.and_then(|r| r.error_for_status())
							.map_err(|_| "Cannot verify Esplora genesis")?;
						let mut bytes = Vec::new();
						response
							.take(65)
							.read_to_end(&mut bytes)
							.map_err(|_| "Cannot read Esplora genesis")?;
						String::from_utf8(bytes)
							.map_err(|_| "Invalid Esplora genesis")?
							.trim()
							.to_owned()
					},
					_ => unreachable!(),
				}
			},
		};
		if actual != expected {
			return Err("Configured chain backend belongs to another Bitcoin network".into());
		}
		Ok(())
	}

	pub fn build(&self) -> Result<Node, String> {
		let mut builder = Builder::new();
		builder.set_network(network(&self.network)?);
		builder.set_storage_dir_path(self.data_dir.to_string_lossy().into_owned());
		builder.set_node_alias(self.alias.clone()).map_err(|_| "Invalid node alias")?;
		builder
			.set_listening_addresses(vec![self
				.listen_address
				.parse()
				.map_err(|_| "Invalid listen address")?])
			.map_err(|_| "Cannot configure Lightning listener")?;
		match &self.chain_source {
			ChainSource::Bitcoind { host, port, user, password } => {
				builder.set_chain_source_bitcoind_rpc(
					host.clone(),
					*port,
					user.clone(),
					password.clone(),
				);
			},
			ChainSource::Electrum { url } => {
				builder.set_chain_source_electrum(url.clone(), None);
			},
			ChainSource::Esplora { url } => {
				builder.set_chain_source_esplora(url.clone(), None);
			},
		}
		builder
			.set_chicory_service(self.policy())
			.map_err(|_| "Cannot configure Chicory service")?;
		builder.build().map_err(|_| "Cannot load native node state".to_owned())
	}
}
