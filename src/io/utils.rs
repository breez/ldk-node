// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{hash_map, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::ops::Deref;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bdk_chain::indexer::keychain_txout::ChangeSet as BdkIndexerChangeSet;
use bdk_chain::local_chain::ChangeSet as BdkLocalChainChangeSet;
use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
use bdk_chain::tx_graph::ChangeSet as BdkTxGraphChangeSet;
use bdk_chain::ConfirmationBlockTime;
use bdk_wallet::ChangeSet as BdkWalletChangeSet;
use bitcoin::Network;
use lightning::ln::msgs::DecodeError;
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::scoring::{
	ChannelLiquidities, ProbabilisticScorer, ProbabilisticScoringDecayParameters,
};
use lightning::util::persist::{
	migrate_kv_store_data_async, KVStore, KVSTORE_NAMESPACE_KEY_ALPHABET,
	KVSTORE_NAMESPACE_KEY_MAX_LEN, NETWORK_GRAPH_PERSISTENCE_KEY,
	NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
	OUTPUT_SWEEPER_PERSISTENCE_KEY, OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
	OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE, SCORER_PERSISTENCE_KEY,
	SCORER_PERSISTENCE_PRIMARY_NAMESPACE, SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::{Readable, ReadableArgs, Writeable};
use lightning_persister::fs_store::v1::FilesystemStore;
use lightning_persister::fs_store::v2::{FilesystemStoreV2, FilesystemStoreV2Error};
use lightning_types::string::PrintableString;

use super::*;
use crate::chain::ChainSource;
use crate::config::WALLET_KEYS_SEED_LEN;
use crate::data_store::{StorableObject, StorableObjectId};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::io::{
	NODE_METRICS_KEY, NODE_METRICS_PRIMARY_NAMESPACE, NODE_METRICS_SECONDARY_NAMESPACE,
	PAYMENT_STORE_SCHEMA_KEY, PAYMENT_STORE_SCHEMA_PRIMARY_NAMESPACE,
	PAYMENT_STORE_SCHEMA_SECONDARY_NAMESPACE,
};
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::store::{PaymentDetails, PaymentKey};
use crate::peer_store::PeerStore;
use crate::types::{Broadcaster, DynStore, KeysManager, Sweeper};
use crate::wallet::ser::{ChangeSetDeserWrapper, ChangeSetSerWrapper};
use crate::{BuildError, Error, EventQueue, NodeMetrics, PersistedNodeMetrics};

pub const EXTERNAL_PATHFINDING_SCORES_CACHE_KEY: &str = "external_pathfinding_scores_cache";

pub(crate) fn read_or_generate_seed_file(
	keys_seed_path: &str,
) -> std::io::Result<[u8; WALLET_KEYS_SEED_LEN]> {
	if Path::new(&keys_seed_path).exists() {
		let seed = fs::read(keys_seed_path)?;

		if seed.len() != WALLET_KEYS_SEED_LEN {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"Failed to read keys seed file due to invalid length",
			));
		}

		let mut key = [0; WALLET_KEYS_SEED_LEN];
		key.copy_from_slice(&seed);
		Ok(key)
	} else {
		let mut key = [0; WALLET_KEYS_SEED_LEN];
		getrandom::fill(&mut key).map_err(|_| {
			std::io::Error::new(std::io::ErrorKind::Other, "Failed to generate seed bytes")
		})?;

		if let Some(parent_dir) = Path::new(&keys_seed_path).parent() {
			fs::create_dir_all(parent_dir)?;
		}

		#[cfg(unix)]
		let mut f = OpenOptions::new().write(true).create_new(true).mode(0o400).open(keys_seed_path)?;

		#[cfg(not(unix))]
		let mut f = OpenOptions::new().write(true).create_new(true).open(keys_seed_path)?;

		f.write_all(&key)?;

		f.sync_all()?;
		Ok(key)
	}
}

/// Read a previously persisted [`NetworkGraph`] from the store.
pub(crate) async fn read_network_graph<L: Deref + Clone>(
	kv_store: &DynStore, logger: L,
) -> Result<NetworkGraph<L>, std::io::Error>
where
	L::Target: LdkLogger,
{
	let reader = KVStore::read(
		&*kv_store,
		NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
		NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
		NETWORK_GRAPH_PERSISTENCE_KEY,
	)
	.await?;
	NetworkGraph::read(&mut &*reader, logger.clone()).map_err(|e| {
		log_error!(logger, "Failed to deserialize NetworkGraph: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize NetworkGraph")
	})
}

/// Read a previously persisted [`ProbabilisticScorer`] from the store.
pub(crate) async fn read_scorer<G: Deref<Target = NetworkGraph<L>>, L: Deref + Clone>(
	kv_store: &DynStore, network_graph: G, logger: L,
) -> Result<ProbabilisticScorer<G, L>, std::io::Error>
where
	L::Target: LdkLogger,
{
	let params = ProbabilisticScoringDecayParameters::default();
	let reader = KVStore::read(
		&*kv_store,
		SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
		SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
		SCORER_PERSISTENCE_KEY,
	)
	.await?;
	let args = (params, network_graph, logger.clone());
	ProbabilisticScorer::read(&mut &*reader, args).map_err(|e| {
		log_error!(logger, "Failed to deserialize scorer: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize Scorer")
	})
}

/// Read previously persisted external pathfinding scores from the cache.
pub(crate) async fn read_external_pathfinding_scores_from_cache<L: Deref>(
	kv_store: &DynStore, logger: L,
) -> Result<ChannelLiquidities, std::io::Error>
where
	L::Target: LdkLogger,
{
	let reader = KVStore::read(
		&*kv_store,
		SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
		SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
		EXTERNAL_PATHFINDING_SCORES_CACHE_KEY,
	)
	.await?;
	ChannelLiquidities::read(&mut &*reader).map_err(|e| {
		log_error!(logger, "Failed to deserialize scorer: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize Scorer")
	})
}

/// Persist external pathfinding scores to the cache.
pub(crate) async fn write_external_pathfinding_scores_to_cache<L: Deref>(
	kv_store: &DynStore, data: &ChannelLiquidities, logger: L,
) -> Result<(), Error>
where
	L::Target: LdkLogger,
{
	KVStore::write(
		&*kv_store,
		SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
		SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
		EXTERNAL_PATHFINDING_SCORES_CACHE_KEY,
		data.encode(),
	)
	.await
	.map_err(|e| {
		log_error!(
			logger,
			"Writing data to key {}/{}/{} failed due to: {}",
			SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
			SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
			EXTERNAL_PATHFINDING_SCORES_CACHE_KEY,
			e
		);
		Error::PersistenceFailed
	})
}

/// Read previously persisted events from the store.
pub(crate) async fn read_event_queue<L: Deref + Clone>(
	kv_store: Arc<DynStore>, logger: L,
) -> Result<EventQueue<L>, std::io::Error>
where
	L::Target: LdkLogger,
{
	let reader = KVStore::read(
		&*kv_store,
		EVENT_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
		EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
		EVENT_QUEUE_PERSISTENCE_KEY,
	)
	.await?;
	EventQueue::read(&mut &*reader, (kv_store, logger.clone())).map_err(|e| {
		log_error!(logger, "Failed to deserialize event queue: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize EventQueue")
	})
}

/// Read previously persisted peer info from the store.
pub(crate) async fn read_peer_info<L: Deref + Clone>(
	kv_store: Arc<DynStore>, logger: L,
) -> Result<PeerStore<L>, std::io::Error>
where
	L::Target: LdkLogger,
{
	let reader = KVStore::read(
		&*kv_store,
		PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
		PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
		PEER_INFO_PERSISTENCE_KEY,
	)
	.await?;
	PeerStore::read(&mut &*reader, (kv_store, logger.clone())).map_err(|e| {
		log_error!(logger, "Failed to deserialize peer store: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize PeerStore")
	})
}

/// Read all objects of type `T` from the given namespace, spawning reads in parallel.
pub(crate) async fn read_all_objects<T, L>(
	kv_store: &DynStore, primary_namespace: &str, secondary_namespace: &str, logger: L,
) -> Result<Vec<T>, std::io::Error>
where
	T: Readable,
	L: Deref,
	L::Target: LdkLogger,
{
	let type_name = std::any::type_name::<T>();
	let mut res = Vec::new();

	let mut stored_keys = KVStore::list(&*kv_store, primary_namespace, secondary_namespace).await?;

	const BATCH_SIZE: usize = 50;

	let mut set = tokio::task::JoinSet::new();

	// Fill JoinSet with tasks if possible
	while set.len() < BATCH_SIZE && !stored_keys.is_empty() {
		if let Some(next_key) = stored_keys.pop() {
			let fut = KVStore::read(kv_store, primary_namespace, secondary_namespace, &next_key);
			set.spawn(fut);
			debug_assert!(set.len() <= BATCH_SIZE);
		}
	}

	while let Some(read_res) = set.join_next().await {
		// Exit early if we get an IO error.
		let reader = read_res
			.map_err(|e| {
				log_error!(logger, "Failed to read {}: {}", type_name, e);
				set.abort_all();
				e
			})?
			.map_err(|e| {
				log_error!(logger, "Failed to read {}: {}", type_name, e);
				set.abort_all();
				e
			})?;

		// Refill set for every finished future, if we still have something to do.
		if let Some(next_key) = stored_keys.pop() {
			let fut = KVStore::read(kv_store, primary_namespace, secondary_namespace, &next_key);
			set.spawn(fut);
			debug_assert!(set.len() <= BATCH_SIZE);
		}

		// Handle result.
		let object = T::read(&mut &*reader).map_err(|e| {
			log_error!(logger, "Failed to deserialize {}: {}", type_name, e);
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("Failed to deserialize {}", type_name),
			)
		})?;
		res.push(object);
	}

	debug_assert!(set.is_empty());
	debug_assert!(stored_keys.is_empty());

	Ok(res)
}

/// Read `OutputSweeper` state from the store.
pub(crate) async fn read_output_sweeper(
	broadcaster: Arc<Broadcaster>, fee_estimator: Arc<OnchainFeeEstimator>,
	chain_data_source: Arc<ChainSource>, keys_manager: Arc<KeysManager>, kv_store: Arc<DynStore>,
	logger: Arc<Logger>,
) -> Result<Sweeper, std::io::Error> {
	let reader = KVStore::read(
		&*kv_store,
		OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
		OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
		OUTPUT_SWEEPER_PERSISTENCE_KEY,
	)
	.await?;
	let args = (
		broadcaster,
		fee_estimator,
		Some(chain_data_source),
		Arc::clone(&keys_manager),
		keys_manager,
		kv_store,
		logger.clone(),
	);
	let (_, sweeper) = <(_, Sweeper)>::read(&mut &*reader, args).map_err(|e| {
		log_error!(logger, "Failed to deserialize OutputSweeper: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize OutputSweeper")
	})?;
	Ok(sweeper)
}

pub(crate) async fn read_node_metrics<L: Deref>(
	kv_store: &DynStore, logger: L,
) -> Result<NodeMetrics, std::io::Error>
where
	L::Target: LdkLogger,
{
	let reader = KVStore::read(
		&*kv_store,
		NODE_METRICS_PRIMARY_NAMESPACE,
		NODE_METRICS_SECONDARY_NAMESPACE,
		NODE_METRICS_KEY,
	)
	.await?;
	NodeMetrics::read(&mut &*reader).map_err(|e| {
		log_error!(logger, "Failed to deserialize NodeMetrics: {}", e);
		std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize NodeMetrics")
	})
}

/// Take a write lock on `node_metrics`, apply `update`, and persist the result to `kv_store`.
pub(crate) async fn update_and_persist_node_metrics<L: Deref>(
	node_metrics: &PersistedNodeMetrics, kv_store: &DynStore, logger: L,
	update: impl FnOnce(&mut NodeMetrics),
) -> Result<(), Error>
where
	L::Target: LdkLogger,
{
	let _guard = node_metrics.lock_mutation().await;
	let data = {
		let mut locked_node_metrics = node_metrics.write().expect("lock");
		update(&mut *locked_node_metrics);
		locked_node_metrics.encode()
	};
	KVStore::write(
		&*kv_store,
		NODE_METRICS_PRIMARY_NAMESPACE,
		NODE_METRICS_SECONDARY_NAMESPACE,
		NODE_METRICS_KEY,
		data,
	)
	.await
	.map_err(|e| {
		log_error!(
			logger,
			"Writing data to key {}/{}/{} failed due to: {}",
			NODE_METRICS_PRIMARY_NAMESPACE,
			NODE_METRICS_SECONDARY_NAMESPACE,
			NODE_METRICS_KEY,
			e
		);
		Error::PersistenceFailed
	})
}

pub(crate) fn is_valid_kvstore_str(key: &str) -> bool {
	key.len() <= KVSTORE_NAMESPACE_KEY_MAX_LEN
		&& key.chars().all(|c| KVSTORE_NAMESPACE_KEY_ALPHABET.contains(c))
}

pub(crate) fn check_namespace_key_validity(
	primary_namespace: &str, secondary_namespace: &str, key: Option<&str>, operation: &str,
) -> Result<(), std::io::Error> {
	if let Some(key) = key {
		if key.is_empty() {
			debug_assert!(
				false,
				"Failed to {} {}/{}/{}: key may not be empty.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace),
				PrintableString(key)
			);
			let msg = format!(
				"Failed to {} {}/{}/{}: key may not be empty.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace),
				PrintableString(key)
			);
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}

		if primary_namespace.is_empty() && !secondary_namespace.is_empty() {
			debug_assert!(false,
				"Failed to {} {}/{}/{}: primary namespace may not be empty if a non-empty secondary namespace is given.",
				operation,
				PrintableString(primary_namespace), PrintableString(secondary_namespace), PrintableString(key));
			let msg = format!(
				"Failed to {} {}/{}/{}: primary namespace may not be empty if a non-empty secondary namespace is given.", operation,
				PrintableString(primary_namespace), PrintableString(secondary_namespace), PrintableString(key));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}

		if !is_valid_kvstore_str(primary_namespace)
			|| !is_valid_kvstore_str(secondary_namespace)
			|| !is_valid_kvstore_str(key)
		{
			debug_assert!(
				false,
				"Failed to {} {}/{}/{}: primary namespace, secondary namespace, and key must be valid.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace),
				PrintableString(key)
			);
			let msg = format!(
				"Failed to {} {}/{}/{}: primary namespace, secondary namespace, and key must be valid.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace),
				PrintableString(key)
			);
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
	} else {
		if primary_namespace.is_empty() && !secondary_namespace.is_empty() {
			debug_assert!(false,
				"Failed to {} {}/{}: primary namespace may not be empty if a non-empty secondary namespace is given.",
				operation, PrintableString(primary_namespace), PrintableString(secondary_namespace));
			let msg = format!(
				"Failed to {} {}/{}: primary namespace may not be empty if a non-empty secondary namespace is given.",
				operation, PrintableString(primary_namespace), PrintableString(secondary_namespace));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
		if !is_valid_kvstore_str(primary_namespace) || !is_valid_kvstore_str(secondary_namespace) {
			debug_assert!(
				false,
				"Failed to {} {}/{}: primary namespace and secondary namespace must be valid.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace)
			);
			let msg = format!(
				"Failed to {} {}/{}: primary namespace and secondary namespace must be valid.",
				operation,
				PrintableString(primary_namespace),
				PrintableString(secondary_namespace)
			);
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
	}

	Ok(())
}

macro_rules! impl_read_write_change_set_type {
	(
		$read_name:ident,
		$write_name:ident,
		$change_set_type:ty,
		$primary_namespace:expr,
		$secondary_namespace:expr,
		$key:expr
	) => {
		pub(crate) async fn $read_name<L: Deref>(
			kv_store: &DynStore, logger: L,
		) -> Result<Option<$change_set_type>, std::io::Error>
		where
			L::Target: LdkLogger,
		{
			let reader =
				match KVStore::read(&*kv_store, $primary_namespace, $secondary_namespace, $key)
					.await
				{
					Ok(bytes) => bytes,
					Err(e) => {
						if e.kind() == lightning::io::ErrorKind::NotFound {
							return Ok(None);
						} else {
							log_error!(
								logger,
								"Reading data from key {}/{}/{} failed due to: {}",
								$primary_namespace,
								$secondary_namespace,
								$key,
								e
							);
							return Err(e.into());
						}
					},
				};

			let res: Result<ChangeSetDeserWrapper<$change_set_type>, DecodeError> =
				Readable::read(&mut &*reader);
			match res {
				Ok(res) => Ok(Some(res.0)),
				Err(e) => {
					log_error!(logger, "Failed to deserialize BDK wallet field: {}", e);
					Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"Failed to deserialize BDK wallet field",
					))
				},
			}
		}

		pub(crate) async fn $write_name<L: Deref>(
			value: &$change_set_type, kv_store: &DynStore, logger: L,
		) -> Result<(), std::io::Error>
		where
			L::Target: LdkLogger,
		{
			let data = ChangeSetSerWrapper(value).encode();
			KVStore::write(&*kv_store, $primary_namespace, $secondary_namespace, $key, data)
				.await
				.map_err(|e| {
					log_error!(
						logger,
						"Writing data to key {}/{}/{} failed due to: {}",
						$primary_namespace,
						$secondary_namespace,
						$key,
						e
					);
					e.into()
				})
		}
	};
}

impl_read_write_change_set_type!(
	read_bdk_wallet_descriptor,
	write_bdk_wallet_descriptor,
	Descriptor<DescriptorPublicKey>,
	BDK_WALLET_DESCRIPTOR_PRIMARY_NAMESPACE,
	BDK_WALLET_DESCRIPTOR_SECONDARY_NAMESPACE,
	BDK_WALLET_DESCRIPTOR_KEY
);

impl_read_write_change_set_type!(
	read_bdk_wallet_change_descriptor,
	write_bdk_wallet_change_descriptor,
	Descriptor<DescriptorPublicKey>,
	BDK_WALLET_CHANGE_DESCRIPTOR_PRIMARY_NAMESPACE,
	BDK_WALLET_CHANGE_DESCRIPTOR_SECONDARY_NAMESPACE,
	BDK_WALLET_CHANGE_DESCRIPTOR_KEY
);

impl_read_write_change_set_type!(
	read_bdk_wallet_network,
	write_bdk_wallet_network,
	Network,
	BDK_WALLET_NETWORK_PRIMARY_NAMESPACE,
	BDK_WALLET_NETWORK_SECONDARY_NAMESPACE,
	BDK_WALLET_NETWORK_KEY
);

impl_read_write_change_set_type!(
	read_bdk_wallet_local_chain,
	write_bdk_wallet_local_chain,
	BdkLocalChainChangeSet,
	BDK_WALLET_LOCAL_CHAIN_PRIMARY_NAMESPACE,
	BDK_WALLET_LOCAL_CHAIN_SECONDARY_NAMESPACE,
	BDK_WALLET_LOCAL_CHAIN_KEY
);

impl_read_write_change_set_type!(
	read_bdk_wallet_tx_graph,
	write_bdk_wallet_tx_graph,
	BdkTxGraphChangeSet<ConfirmationBlockTime>,
	BDK_WALLET_TX_GRAPH_PRIMARY_NAMESPACE,
	BDK_WALLET_TX_GRAPH_SECONDARY_NAMESPACE,
	BDK_WALLET_TX_GRAPH_KEY
);

impl_read_write_change_set_type!(
	read_bdk_wallet_indexer,
	write_bdk_wallet_indexer,
	BdkIndexerChangeSet,
	BDK_WALLET_INDEXER_PRIMARY_NAMESPACE,
	BDK_WALLET_INDEXER_SECONDARY_NAMESPACE,
	BDK_WALLET_INDEXER_KEY
);

// Reads the full BdkWalletChangeSet or returns default fields
pub(crate) async fn read_bdk_wallet_change_set(
	kv_store: &DynStore, logger: &Logger,
) -> Result<Option<BdkWalletChangeSet>, std::io::Error> {
	let mut change_set = BdkWalletChangeSet::default();

	// We require a descriptor and return `None` to signal creation of a new wallet otherwise.
	if let Some(descriptor) = read_bdk_wallet_descriptor(kv_store, logger).await? {
		change_set.descriptor = Some(descriptor);
	} else {
		return Ok(None);
	}

	// We require a change_descriptor and return `None` to signal creation of a new wallet otherwise.
	if let Some(change_descriptor) = read_bdk_wallet_change_descriptor(kv_store, logger).await? {
		change_set.change_descriptor = Some(change_descriptor);
	} else {
		return Ok(None);
	}

	// We require a network and return `None` to signal creation of a new wallet otherwise.
	if let Some(network) = read_bdk_wallet_network(kv_store, logger).await? {
		change_set.network = Some(network);
	} else {
		return Ok(None);
	}

	read_bdk_wallet_local_chain(&*kv_store, logger)
		.await?
		.map(|local_chain| change_set.local_chain = local_chain);
	read_bdk_wallet_tx_graph(&*kv_store, logger)
		.await?
		.map(|tx_graph| change_set.tx_graph = tx_graph);
	read_bdk_wallet_indexer(&*kv_store, logger).await?.map(|indexer| change_set.indexer = indexer);
	Ok(Some(change_set))
}

/// Opens a [`FilesystemStoreV2`], automatically migrating from v1 format if necessary.
///
/// If the directory contains v1 data (files at the top level), the data is migrated to v2 format
/// in a temporary directory, the original is renamed to `fs_store_v1_backup`, and the migrated
/// directory is moved into place.
pub(crate) async fn open_or_migrate_fs_store(
	storage_dir_path: PathBuf,
) -> Result<FilesystemStoreV2, BuildError> {
	let parent_dir = storage_dir_path.parent().ok_or(BuildError::StoragePathAccessFailed)?;
	fs::create_dir_all(parent_dir).map_err(|_| BuildError::StoragePathAccessFailed)?;
	recover_incomplete_fs_store_migration(&storage_dir_path)?;
	if !storage_dir_path.exists() {
		fs::create_dir_all(storage_dir_path.clone())
			.map_err(|_| BuildError::StoragePathAccessFailed)?;
	}

	match FilesystemStoreV2::new(storage_dir_path.clone()) {
		Ok(store) => Ok(store),
		Err(FilesystemStoreV2Error::V1DataDetected(_)) => {
			// The directory contains v1 data, migrate to v2.
			let v1_store = FilesystemStore::new(storage_dir_path.clone());

			let v2_dir = fs_store_sibling_path(&storage_dir_path, "fs_store_v2_migrating");
			fs::create_dir_all(v2_dir.clone()).map_err(|_| BuildError::StoragePathAccessFailed)?;
			let v2_store = FilesystemStoreV2::new(v2_dir.clone())
				.map_err(|_| BuildError::KVStoreSetupFailed)?;

			migrate_kv_store_data_async(&v1_store, &v2_store)
				.await
				.map_err(|_| BuildError::KVStoreSetupFailed)?;

			// Swap directories: rename v1 out of the way, move v2 into place.
			let backup_dir = fs_store_sibling_path(&storage_dir_path, "fs_store_v1_backup");
			fs::rename(&storage_dir_path, &backup_dir)
				.map_err(|_| BuildError::KVStoreSetupFailed)?;
			fs::rename(&v2_dir, &storage_dir_path).map_err(|_| BuildError::KVStoreSetupFailed)?;

			// fsync the renames
			fs::File::open(parent_dir)
				.and_then(|f| f.sync_all())
				.map_err(|_| BuildError::KVStoreSetupFailed)?;

			FilesystemStoreV2::new(storage_dir_path).map_err(|_| BuildError::KVStoreSetupFailed)
		},
		Err(_) => Err(BuildError::KVStoreSetupFailed),
	}
}

fn fs_store_sibling_path(storage_dir_path: &Path, file_name: &str) -> PathBuf {
	let mut sibling_path = storage_dir_path.to_path_buf();
	sibling_path.set_file_name(file_name);
	sibling_path
}

fn recover_incomplete_fs_store_migration(storage_dir_path: &Path) -> Result<(), BuildError> {
	let v2_dir = fs_store_sibling_path(storage_dir_path, "fs_store_v2_migrating");
	let backup_dir = fs_store_sibling_path(storage_dir_path, "fs_store_v1_backup");

	if storage_dir_path.exists() {
		if v2_dir.exists() {
			// The original store is still in place, so a temp migration dir is from a crash before
			// the rename step and can be discarded before retrying migration.
			fs::remove_dir_all(&v2_dir).map_err(|_| BuildError::KVStoreSetupFailed)?;
		}
		return Ok(());
	}

	if backup_dir.exists() {
		if v2_dir.exists() {
			// Prefer retrying from the v1 backup instead of deciding here whether the temp v2 dir is
			// usable. open_or_migrate_fs_store owns the actual v1-to-v2 migration.
			fs::remove_dir_all(&v2_dir).map_err(|_| BuildError::KVStoreSetupFailed)?;
		}
		// The crash happened after moving v1 aside; restore it so normal startup can migrate it.
		fs::rename(&backup_dir, storage_dir_path).map_err(|_| BuildError::KVStoreSetupFailed)?;
		return Ok(());
	}

	if v2_dir.exists() {
		// There is no v1 backup to retry from. Move the temp dir into place and let
		// open_or_migrate_fs_store decide whether it is a valid v2 store.
		fs::rename(&v2_dir, storage_dir_path).map_err(|_| BuildError::KVStoreSetupFailed)?;
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::path::{Path, PathBuf};

	use lightning::util::persist::{migrate_kv_store_data_async, KVStore};
	use lightning_persister::fs_store::v1::FilesystemStore;
	use lightning_persister::fs_store::v2::FilesystemStoreV2;

	use super::test_utils::random_storage_path;
	use super::{open_or_migrate_fs_store, read_or_generate_seed_file};

	const TEST_PRIMARY_NAMESPACE: &str = "test_primary_namespace";
	const TEST_SECONDARY_NAMESPACE: &str = "test_secondary_namespace";
	const TEST_KEY: &str = "test_key";
	const TEST_VALUE: &[u8] = b"test_value";

	#[test]
	fn generated_seed_is_readable() {
		let mut rand_path = random_storage_path();
		rand_path.push("test_keys_seed");
		let expected_seed_bytes = read_or_generate_seed_file(&rand_path.to_str().unwrap()).unwrap();
		let read_seed_bytes = read_or_generate_seed_file(&rand_path.to_str().unwrap()).unwrap();
		assert_eq!(expected_seed_bytes, read_seed_bytes);
	}

	#[tokio::test]
	async fn fs_store_migration_recovers_before_v1_backup_rename() {
		let fs_store_path = fs_store_path();
		let v1_store = write_v1_test_data(&fs_store_path).await;
		let v2_migrating_path = sibling_path(&fs_store_path, "fs_store_v2_migrating");
		let v2_store = FilesystemStoreV2::new(v2_migrating_path.clone()).unwrap();
		migrate_kv_store_data_async(&v1_store, &v2_store).await.unwrap();

		let migrated_store = open_or_migrate_fs_store(fs_store_path.clone()).await.unwrap();
		assert_eq!(
			KVStore::read(
				&migrated_store,
				TEST_PRIMARY_NAMESPACE,
				TEST_SECONDARY_NAMESPACE,
				TEST_KEY
			)
			.await
			.unwrap(),
			TEST_VALUE
		);
		assert!(fs_store_path.exists());
		assert!(!v2_migrating_path.exists());
	}

	#[tokio::test]
	async fn fs_store_migration_recovers_after_v1_backup_rename() {
		let fs_store_path = fs_store_path();
		let v1_store = write_v1_test_data(&fs_store_path).await;
		let v2_migrating_path = sibling_path(&fs_store_path, "fs_store_v2_migrating");
		let v2_store = FilesystemStoreV2::new(v2_migrating_path.clone()).unwrap();
		migrate_kv_store_data_async(&v1_store, &v2_store).await.unwrap();

		let backup_path = sibling_path(&fs_store_path, "fs_store_v1_backup");
		fs::rename(&fs_store_path, backup_path).unwrap();

		let migrated_store = open_or_migrate_fs_store(fs_store_path.clone()).await.unwrap();
		assert_eq!(
			KVStore::read(
				&migrated_store,
				TEST_PRIMARY_NAMESPACE,
				TEST_SECONDARY_NAMESPACE,
				TEST_KEY
			)
			.await
			.unwrap(),
			TEST_VALUE
		);
		assert!(fs_store_path.exists());
		assert!(!v2_migrating_path.exists());
	}

	#[tokio::test]
	async fn fs_store_migration_recovers_after_v2_rename() {
		let fs_store_path = fs_store_path();
		let v1_store = write_v1_test_data(&fs_store_path).await;
		let v2_migrating_path = sibling_path(&fs_store_path, "fs_store_v2_migrating");
		let v2_store = FilesystemStoreV2::new(v2_migrating_path.clone()).unwrap();
		migrate_kv_store_data_async(&v1_store, &v2_store).await.unwrap();

		let backup_path = sibling_path(&fs_store_path, "fs_store_v1_backup");
		fs::rename(&fs_store_path, &backup_path).unwrap();
		fs::rename(&v2_migrating_path, &fs_store_path).unwrap();

		let migrated_store = open_or_migrate_fs_store(fs_store_path.clone()).await.unwrap();
		assert_eq!(
			KVStore::read(
				&migrated_store,
				TEST_PRIMARY_NAMESPACE,
				TEST_SECONDARY_NAMESPACE,
				TEST_KEY
			)
			.await
			.unwrap(),
			TEST_VALUE
		);
		assert!(fs_store_path.exists());
		assert!(backup_path.exists());
		assert!(!v2_migrating_path.exists());
	}

	#[tokio::test]
	async fn fs_store_migration_recovers_backup_without_migrating_dir() {
		let fs_store_path = fs_store_path();
		write_v1_test_data(&fs_store_path).await;

		let backup_path = sibling_path(&fs_store_path, "fs_store_v1_backup");
		fs::rename(&fs_store_path, backup_path).unwrap();

		let migrated_store = open_or_migrate_fs_store(fs_store_path.clone()).await.unwrap();
		assert_eq!(
			KVStore::read(
				&migrated_store,
				TEST_PRIMARY_NAMESPACE,
				TEST_SECONDARY_NAMESPACE,
				TEST_KEY
			)
			.await
			.unwrap(),
			TEST_VALUE
		);
		assert!(fs_store_path.exists());
		assert!(!sibling_path(&fs_store_path, "fs_store_v1_backup").exists());
	}

	#[tokio::test]
	async fn fs_store_migration_recovers_unexpected_migrating_dir_without_backup() {
		let fs_store_path = fs_store_path();
		let v2_migrating_path = sibling_path(&fs_store_path, "fs_store_v2_migrating");
		let v2_store = FilesystemStoreV2::new(v2_migrating_path.clone()).unwrap();
		KVStore::write(
			&v2_store,
			TEST_PRIMARY_NAMESPACE,
			TEST_SECONDARY_NAMESPACE,
			TEST_KEY,
			TEST_VALUE.to_vec(),
		)
		.await
		.unwrap();

		let migrated_store = open_or_migrate_fs_store(fs_store_path.clone()).await.unwrap();
		assert_eq!(
			KVStore::read(
				&migrated_store,
				TEST_PRIMARY_NAMESPACE,
				TEST_SECONDARY_NAMESPACE,
				TEST_KEY
			)
			.await
			.unwrap(),
			TEST_VALUE
		);
		assert!(fs_store_path.exists());
		assert!(!v2_migrating_path.exists());
	}

	fn fs_store_path() -> PathBuf {
		let mut fs_store_path = random_storage_path();
		fs_store_path.push("fs_store");
		fs_store_path
	}

	fn sibling_path(path: &Path, file_name: &str) -> PathBuf {
		let mut sibling_path = path.to_path_buf();
		sibling_path.set_file_name(file_name);
		sibling_path
	}

	async fn write_v1_test_data(fs_store_path: &Path) -> FilesystemStore {
		let v1_store = FilesystemStore::new(fs_store_path.to_path_buf());
		KVStore::write(
			&v1_store,
			TEST_PRIMARY_NAMESPACE,
			TEST_SECONDARY_NAMESPACE,
			TEST_KEY,
			TEST_VALUE.to_vec(),
		)
		.await
		.unwrap();
		v1_store
	}
}

/// The payment store layout this build writes: payments keyed by id *and* direction.
pub(crate) const PAYMENT_STORE_SCHEMA_VERSION: u16 = 1;

/// The layout of a store written before payment keys carried the direction. Also the
/// version reported for a store that has no schema record at all.
const PAYMENT_STORE_SCHEMA_VERSION_LEGACY: u16 = 0;

/// Reads the payment store's schema version, treating a store with no record as
/// [`PAYMENT_STORE_SCHEMA_VERSION_LEGACY`].
pub(crate) async fn read_payment_store_schema_version(
	kv_store: &DynStore,
) -> Result<u16, std::io::Error> {
	let read_res: Result<Vec<u8>, std::io::Error> = KVStore::read(
		&*kv_store,
		PAYMENT_STORE_SCHEMA_PRIMARY_NAMESPACE,
		PAYMENT_STORE_SCHEMA_SECONDARY_NAMESPACE,
		PAYMENT_STORE_SCHEMA_KEY,
	)
	.await
	.map_err(|e| e.into());

	match read_res {
		Ok(bytes) => {
			let raw: [u8; 2] = bytes.as_slice().try_into().map_err(|_| {
				std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"Payment store schema version is malformed",
				)
			})?;
			Ok(u16::from_be_bytes(raw))
		},
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			Ok(PAYMENT_STORE_SCHEMA_VERSION_LEGACY)
		},
		Err(e) => Err(e),
	}
}

async fn write_payment_store_schema_version(
	kv_store: &DynStore, version: u16,
) -> Result<(), std::io::Error> {
	KVStore::write(
		&*kv_store,
		PAYMENT_STORE_SCHEMA_PRIMARY_NAMESPACE,
		PAYMENT_STORE_SCHEMA_SECONDARY_NAMESPACE,
		PAYMENT_STORE_SCHEMA_KEY,
		version.to_be_bytes().to_vec(),
	)
	.await?;
	Ok(())
}

/// Brings the payment store up to [`PAYMENT_STORE_SCHEMA_VERSION`], doing nothing if
/// it is already there.
///
/// The version record is written only once every payment has been moved, so this
/// does no work on any startup after the one that migrates. `KVStore` has no
/// cross-key transaction, so an interrupted run is handled by convergence instead:
/// the version stays behind, the next startup repeats the move, and each step is
/// individually safe to redo.
pub(crate) async fn migrate_payment_store<L: Deref>(
	kv_store: &DynStore, logger: L,
) -> Result<(), std::io::Error>
where
	L::Target: LdkLogger,
{
	if read_payment_store_schema_version(kv_store).await? >= PAYMENT_STORE_SCHEMA_VERSION {
		return Ok(());
	}

	migrate_payment_store_keys(kv_store, logger).await?;
	write_payment_store_schema_version(kv_store, PAYMENT_STORE_SCHEMA_VERSION).await
}

/// Moves payments persisted under the pre-`(id, direction)` key format to their
/// current key.
///
/// Payments used to be stored under the hex payment id alone. Both sides of a
/// payment to ourselves share that id, so the key now carries the direction too. A
/// legacy entry still loads correctly (the direction is part of the value), but the
/// next write for it lands on the new key and leaves the old one behind holding
/// stale data. Both are read on the following startup and collapse onto the same
/// key, where the survivor is decided by read-completion order, so the stale copy
/// can win.
///
/// Each legacy entry is written under its new key before the old one is removed, so
/// an interrupted run leaves a duplicate rather than dropping a payment. Re-running
/// is a no-op.
pub(crate) async fn migrate_payment_store_keys<L: Deref>(
	kv_store: &DynStore, logger: L,
) -> Result<(), std::io::Error>
where
	L::Target: LdkLogger,
{
	let primary = PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE;
	let secondary = PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE;

	for key in KVStore::list(&*kv_store, primary, secondary).await? {
		if is_directional_payment_key(&key) {
			continue;
		}

		let bytes = KVStore::read(&*kv_store, primary, secondary, &key).await?;
		let payment = PaymentDetails::read(&mut &*bytes).map_err(|e| {
			log_error!(logger, "Failed to deserialize payment under legacy key {}: {}", key, e);
			std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize payment")
		})?;

		let new_key = payment.id().encode_to_hex_str();
		if new_key == key {
			continue;
		}

		KVStore::write(&*kv_store, primary, secondary, &new_key, payment.encode()).await?;
		KVStore::remove(&*kv_store, primary, secondary, &key, false).await?;
		log_info!(logger, "Migrated payment {} to key {}", key, new_key);
	}

	Ok(())
}

/// Whether `key` already carries the direction suffix the payment key format uses.
/// A legacy key is the bare hex id, and hex never contains `_`.
fn is_directional_payment_key(key: &str) -> bool {
	key.ends_with("_in") || key.ends_with("_out")
}

/// Collapses payments that share a key, keeping the most recently updated copy.
///
/// A run of [`migrate_payment_store_keys`] interrupted between the write and the
/// remove leaves the same payment under both its legacy and its current key. Both
/// are read back, and building the store's map from them would otherwise let
/// read-completion order pick the winner.
pub(crate) fn dedupe_payments_by_key(payments: Vec<PaymentDetails>) -> Vec<PaymentDetails> {
	let mut by_key: HashMap<PaymentKey, PaymentDetails> = HashMap::new();
	for payment in payments {
		match by_key.entry(payment.id()) {
			hash_map::Entry::Occupied(mut e) => {
				if payment.latest_update_timestamp > e.get().latest_update_timestamp {
					e.insert(payment);
				}
			},
			hash_map::Entry::Vacant(e) => {
				e.insert(payment);
			},
		}
	}
	by_key.into_values().collect()
}

#[cfg(test)]
mod payment_key_migration_tests {
	use lightning::ln::channelmanager::PaymentId;
	use lightning::util::test_utils::TestLogger;
	use lightning_types::payment::PaymentHash;

	use super::*;
	use crate::hex_utils;
	use crate::io::test_utils::InMemoryStore;
	use crate::payment::store::{PaymentDirection, PaymentKind, PaymentStatus};
	use crate::types::DynStoreWrapper;

	fn payment(id_byte: u8, direction: PaymentDirection, timestamp: u64) -> PaymentDetails {
		let hash = PaymentHash([id_byte; 32]);
		let mut details = PaymentDetails::new(
			PaymentId(hash.0),
			PaymentKind::Bolt11 {
				hash,
				preimage: None,
				secret: None,
				counterparty_skimmed_fee_msat: None,
				claim_deadline: None,
				claimable_amount_msat: None,
			},
			Some(1_000),
			None,
			direction,
			PaymentStatus::Pending,
		);
		details.latest_update_timestamp = timestamp;
		details
	}

	async fn legacy_write(store: &DynStore, payment: &PaymentDetails) -> String {
		let legacy_key = hex_utils::to_string(&payment.id.0);
		KVStore::write(
			store,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			&legacy_key,
			payment.encode(),
		)
		.await
		.unwrap();
		legacy_key
	}

	async fn keys(store: &DynStore) -> Vec<String> {
		let mut keys = KVStore::list(
			store,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
		)
		.await
		.unwrap();
		keys.sort();
		keys
	}

	#[tokio::test]
	async fn legacy_key_is_moved_to_its_directional_key() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		let inbound = payment(1, PaymentDirection::Inbound, 10);
		let legacy_key = legacy_write(&*store, &inbound).await;

		migrate_payment_store_keys(&*store, Arc::clone(&logger)).await.unwrap();

		assert_eq!(keys(&*store).await, vec![format!("{legacy_key}_in")]);
	}

	#[tokio::test]
	async fn migration_is_idempotent() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		legacy_write(&*store, &payment(2, PaymentDirection::Outbound, 10)).await;

		migrate_payment_store_keys(&*store, Arc::clone(&logger)).await.unwrap();
		let after_first = keys(&*store).await;
		migrate_payment_store_keys(&*store, Arc::clone(&logger)).await.unwrap();

		assert_eq!(keys(&*store).await, after_first);
	}

	/// The reason the key had to change: both sides of a self-payment share an id, so
	/// they must occupy separate keys rather than overwriting each other.
	#[tokio::test]
	async fn both_sides_of_one_id_survive() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		let inbound = payment(3, PaymentDirection::Inbound, 10);
		let outbound = payment(3, PaymentDirection::Outbound, 11);
		let hex = hex_utils::to_string(&inbound.id.0);

		legacy_write(&*store, &inbound).await;
		migrate_payment_store_keys(&*store, Arc::clone(&logger)).await.unwrap();
		KVStore::write(
			&*store,
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			&outbound.id().encode_to_hex_str(),
			outbound.encode(),
		)
		.await
		.unwrap();

		assert_eq!(keys(&*store).await, vec![format!("{hex}_in"), format!("{hex}_out")]);
	}

	#[tokio::test]
	async fn migration_records_the_schema_version() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		assert_eq!(read_payment_store_schema_version(&*store).await.unwrap(), 0);

		migrate_payment_store(&*store, Arc::clone(&logger)).await.unwrap();

		assert_eq!(
			read_payment_store_schema_version(&*store).await.unwrap(),
			PAYMENT_STORE_SCHEMA_VERSION
		);
	}

	/// Once the version is recorded the migration must not touch the store again, so a
	/// legacy-shaped key written afterwards is left exactly where it is.
	#[tokio::test]
	async fn migration_does_not_run_again_once_recorded() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		migrate_payment_store(&*store, Arc::clone(&logger)).await.unwrap();

		let legacy_key = legacy_write(&*store, &payment(5, PaymentDirection::Inbound, 10)).await;
		migrate_payment_store(&*store, Arc::clone(&logger)).await.unwrap();

		assert_eq!(keys(&*store).await, vec![legacy_key]);
	}

	/// An interrupted run leaves the version behind, so the next startup repeats the
	/// move rather than skipping it.
	#[tokio::test]
	async fn interrupted_migration_is_repeated_on_the_next_startup() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(TestLogger::new());
		let legacy_key = legacy_write(&*store, &payment(6, PaymentDirection::Outbound, 10)).await;

		// The move ran but the version write never landed.
		migrate_payment_store_keys(&*store, Arc::clone(&logger)).await.unwrap();
		legacy_write(&*store, &payment(6, PaymentDirection::Outbound, 10)).await;
		assert_eq!(read_payment_store_schema_version(&*store).await.unwrap(), 0);

		migrate_payment_store(&*store, Arc::clone(&logger)).await.unwrap();

		assert_eq!(keys(&*store).await, vec![format!("{legacy_key}_out")]);
		assert_eq!(
			read_payment_store_schema_version(&*store).await.unwrap(),
			PAYMENT_STORE_SCHEMA_VERSION
		);
	}

	/// A migration interrupted between its write and its remove leaves the payment
	/// under both keys, and the stale legacy copy must not win the next startup.
	#[tokio::test]
	async fn interrupted_migration_keeps_the_newer_copy() {
		let stale = payment(4, PaymentDirection::Inbound, 10);
		let fresh = payment(4, PaymentDirection::Inbound, 20);

		let deduped = dedupe_payments_by_key(vec![fresh.clone(), stale.clone()]);
		assert_eq!(deduped.len(), 1);
		assert_eq!(deduped[0].latest_update_timestamp, 20);

		// Order must not decide the winner.
		let deduped = dedupe_payments_by_key(vec![stale, fresh]);
		assert_eq!(deduped.len(), 1);
		assert_eq!(deduped[0].latest_update_timestamp, 20);
	}
}
