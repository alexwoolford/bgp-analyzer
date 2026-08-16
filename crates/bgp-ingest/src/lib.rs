//! Historical MRT discovery and streaming.

use anyhow::{anyhow, Context, Result};
use bgpkit_broker::{BgpkitBroker, BrokerItem};
use bgpkit_parser::BgpkitParser;
use thiserror::Error;
use tracing::info;

pub use bgpkit_parser::models::ElemType;
pub use bgpkit_parser::BgpElem;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("broker query failed: {0}")]
    Broker(String),
    #[error("parser error for `{url}`: {source}")]
    Parser {
        url: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("no MRT files found for the requested window")]
    NoFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Rib,
    Updates,
}

impl DataType {
    fn as_broker_str(self) -> &'static str {
        match self {
            DataType::Rib => "rib",
            DataType::Updates => "updates",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngestQuery {
    pub ts_start: String,
    pub ts_end: String,
    pub collector: Option<String>,
    pub data_type: DataType,
}

/// Query BGPKIT Broker for MRT archive metadata.
pub fn query_mrt_files(query: &IngestQuery) -> Result<Vec<BrokerItem>> {
    let mut broker = BgpkitBroker::new()
        .ts_start(query.ts_start.as_str())
        .ts_end(query.ts_end.as_str())
        .data_type(query.data_type.as_broker_str());

    if let Some(collector) = &query.collector {
        broker = broker.collector_id(collector.as_str());
    }

    let mut items = broker
        .query()
        .map_err(|e| IngestError::Broker(e.to_string()))?;

    items.sort_by_key(|i| i.ts_start);
    info!(
        count = items.len(),
        data_type = query.data_type.as_broker_str(),
        "broker returned MRT files"
    );
    Ok(items)
}

/// Pick the latest RIB dump in the window for the collector.
pub fn select_rib_baseline(query: &IngestQuery) -> Result<BrokerItem> {
    let mut rib_query = query.clone();
    rib_query.data_type = DataType::Rib;
    let items = query_mrt_files(&rib_query)?;
    items
        .into_iter()
        .next_back()
        .ok_or_else(|| IngestError::NoFiles.into())
}

/// List updates files in chronological order for the window.
pub fn list_updates(query: &IngestQuery) -> Result<Vec<BrokerItem>> {
    let mut updates_query = query.clone();
    updates_query.data_type = DataType::Updates;
    let items = query_mrt_files(&updates_query)?;
    if items.is_empty() {
        return Err(IngestError::NoFiles.into());
    }
    Ok(items)
}

/// Open a streaming parser from a local path or URL.
pub fn open_parser(url: &str) -> Result<BgpkitParser<Box<dyn std::io::Read + Send>>> {
    BgpkitParser::new(url).map_err(|e| {
        IngestError::Parser {
            url: url.to_string(),
            source: anyhow!(e.to_string()),
        }
        .into()
    })
}

/// Open a parser with an announcement/withdrawal type filter (`a` or `w`).
pub fn open_parser_filtered(
    url: &str,
    elem_type: Option<&str>,
) -> Result<BgpkitParser<Box<dyn std::io::Read + Send>>> {
    let mut parser = open_parser(url)?;
    if let Some(t) = elem_type {
        parser = parser
            .add_filter("type", t)
            .with_context(|| format!("adding type filter `{t}` for {url}"))?;
    }
    Ok(parser)
}

/// Convenience: reconstruct order is one RIB file then updates files.
#[derive(Debug, Clone)]
pub struct ReconstructionPlan {
    pub rib: BrokerItem,
    pub updates: Vec<BrokerItem>,
}

pub fn plan_reconstruction(query: &IngestQuery) -> Result<ReconstructionPlan> {
    let rib = select_rib_baseline(query)?;
    let updates = list_updates(query).unwrap_or_default();
    info!(
        rib = %rib.url,
        updates = updates.len(),
        "planned RIB reconstruction"
    );
    Ok(ReconstructionPlan { rib, updates })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_type_strings() {
        assert_eq!(DataType::Rib.as_broker_str(), "rib");
        assert_eq!(DataType::Updates.as_broker_str(), "updates");
    }

    #[test]
    #[ignore = "requires network access to RouteViews"]
    fn network_parse_sample_updates() {
        let url = "http://archive.routeviews.org/route-views4/bgpdata/2022.01/UPDATES/updates.20220101.0000.bz2";
        let parser = open_parser(url).expect("open parser");
        let count = parser.into_iter().take(100).count();
        assert!(count > 0);
    }
}
