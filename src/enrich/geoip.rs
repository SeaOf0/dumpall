use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::collectors::collection_error;
use crate::model::CollectionError;

use super::identity::{parse_ip_token, Cidr};

#[derive(Debug, Default)]
pub struct GeoIpDb {
    records: Vec<GeoIpRecord>,
    pub sources: Vec<GeoIpSourceSummary>,
    #[cfg(feature = "geoip")]
    mmdb_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone)]
struct GeoIpRecord {
    network: Cidr,
    country: String,
    region: String,
    city: String,
    asn: String,
    as_org: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpSourceSummary {
    pub path: String,
    pub format: String,
    pub records_loaded: usize,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct GeoIpLookup {
    pub country: String,
    pub region: String,
    pub city: String,
    pub asn: String,
    pub as_org: String,
}

impl GeoIpDb {
    pub fn load(path: Option<&Path>) -> (Self, Vec<CollectionError>) {
        let Some(path) = path else {
            return (Self::default(), Vec::new());
        };

        if !path.exists() {
            return (
                Self::default(),
                vec![collection_error(
                    "geoip",
                    path.display().to_string(),
                    "load",
                    "GeoIP database path does not exist",
                    None,
                )],
            );
        }

        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if extension == "mmdb" {
            return load_mmdb(path);
        }

        let result = match extension.as_str() {
            "csv" => load_csv(path),
            "json" | "jsonl" => load_json(path).map(|records| (records, 0)),
            _ => Err(format!(
                "unsupported GeoIP database extension `{extension}`; expected csv, json, jsonl, or mmdb"
            )),
        };

        match result {
            Ok((records, skipped_rows)) => {
                // 单条坏行跳过并计数告警(errors 管道一条汇总),库继续加载。
                let mut errors = Vec::new();
                if skipped_rows > 0 {
                    errors.push(collection_error(
                        "geoip",
                        path.display().to_string(),
                        "parse",
                        format!("{skipped_rows} malformed GeoIP row(s) were skipped while loading"),
                        None,
                    ));
                }
                let count = records.len();
                (
                    Self {
                        records,
                        sources: vec![GeoIpSourceSummary {
                            path: path.display().to_string(),
                            format: extension,
                            records_loaded: count,
                            status: "loaded".to_string(),
                        }],
                        #[cfg(feature = "geoip")]
                        mmdb_reader: None,
                    },
                    errors,
                )
            }
            Err(error) => (
                Self {
                    records: Vec::new(),
                    sources: vec![GeoIpSourceSummary {
                        path: path.display().to_string(),
                        format: extension,
                        records_loaded: 0,
                        status: "error".to_string(),
                    }],
                    #[cfg(feature = "geoip")]
                    mmdb_reader: None,
                },
                vec![collection_error(
                    "geoip",
                    path.display().to_string(),
                    "load",
                    "GeoIP database could not be loaded",
                    Some(error),
                )],
            ),
        }
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoIpLookup> {
        let parsed_ip = parse_ip_token(ip)?;
        let record_lookup = self
            .records
            .iter()
            .find(|record| record.network.contains(parsed_ip))
            .map(|record| GeoIpLookup {
                country: record.country.clone(),
                region: record.region.clone(),
                city: record.city.clone(),
                asn: record.asn.clone(),
                as_org: record.as_org.clone(),
            });
        if record_lookup.is_some() {
            return record_lookup;
        }

        #[cfg(feature = "geoip")]
        {
            self.mmdb_reader
                .as_ref()
                .and_then(|reader| lookup_mmdb(reader, parsed_ip))
        }
        #[cfg(not(feature = "geoip"))]
        {
            None
        }
    }
}

#[cfg(feature = "geoip")]
fn load_mmdb(path: &Path) -> (GeoIpDb, Vec<CollectionError>) {
    match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => (
            GeoIpDb {
                records: Vec::new(),
                sources: vec![GeoIpSourceSummary {
                    path: path.display().to_string(),
                    format: "mmdb".to_string(),
                    records_loaded: 0,
                    status: "loaded".to_string(),
                }],
                mmdb_reader: Some(reader),
            },
            Vec::new(),
        ),
        Err(error) => (
            GeoIpDb {
                records: Vec::new(),
                sources: vec![GeoIpSourceSummary {
                    path: path.display().to_string(),
                    format: "mmdb".to_string(),
                    records_loaded: 0,
                    status: "error".to_string(),
                }],
                mmdb_reader: None,
            },
            vec![collection_error(
                "geoip",
                path.display().to_string(),
                "load_mmdb",
                "GeoIP MMDB database could not be loaded",
                Some(error.to_string()),
            )],
        ),
    }
}

#[cfg(not(feature = "geoip"))]
fn load_mmdb(path: &Path) -> (GeoIpDb, Vec<CollectionError>) {
    (
        GeoIpDb::default(),
        vec![collection_error(
            "geoip",
            path.display().to_string(),
            "load_mmdb",
            "GeoIP MMDB support requires a build with --features geoip",
            None,
        )],
    )
}

#[cfg(feature = "geoip")]
fn lookup_mmdb(reader: &maxminddb::Reader<Vec<u8>>, ip: std::net::IpAddr) -> Option<GeoIpLookup> {
    let mut lookup = GeoIpLookup::default();

    if let Ok(result) = reader.lookup(ip) {
        if let Ok(Some(city)) = result.decode::<maxminddb::geoip2::City>() {
            lookup.country = city.country.iso_code.unwrap_or_default().to_string();
            lookup.region = city
                .subdivisions
                .first()
                .and_then(|subdivision| {
                    subdivision
                        .iso_code
                        .or(subdivision.names.english)
                        .map(str::to_string)
                })
                .unwrap_or_default();
            lookup.city = city.city.names.english.unwrap_or_default().to_string();
        }
    }

    if lookup.country.is_empty() {
        if let Ok(result) = reader.lookup(ip) {
            if let Ok(Some(country)) = result.decode::<maxminddb::geoip2::Country>() {
                lookup.country = country.country.iso_code.unwrap_or_default().to_string();
            }
        }
    }

    if let Ok(result) = reader.lookup(ip) {
        if let Ok(Some(asn)) = result.decode::<maxminddb::geoip2::Asn>() {
            lookup.asn = asn
                .autonomous_system_number
                .map(|asn| asn.to_string())
                .unwrap_or_default();
            lookup.as_org = asn
                .autonomous_system_organization
                .unwrap_or_default()
                .to_string();
        }
    }

    if lookup.asn.is_empty() || lookup.as_org.is_empty() {
        if let Ok(result) = reader.lookup(ip) {
            if let Ok(Some(isp)) = result.decode::<maxminddb::geoip2::Isp>() {
                if lookup.asn.is_empty() {
                    lookup.asn = isp
                        .autonomous_system_number
                        .map(|asn| asn.to_string())
                        .unwrap_or_default();
                }
                if lookup.as_org.is_empty() {
                    lookup.as_org = isp
                        .autonomous_system_organization
                        .or(isp.organization)
                        .unwrap_or_default()
                        .to_string();
                }
            }
        }
    }

    let has_data = !lookup.country.is_empty()
        || !lookup.region.is_empty()
        || !lookup.city.is_empty()
        || !lookup.asn.is_empty()
        || !lookup.as_org.is_empty();
    has_data.then_some(lookup)
}

fn load_csv(path: &Path) -> std::result::Result<(Vec<GeoIpRecord>, usize), String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|error| error.to_string())?;
    let headers = reader.headers().map_err(|error| error.to_string())?.clone();
    let mut records = Vec::new();
    let mut skipped_rows = 0usize;
    for row in reader.records() {
        // 单条坏行(缺 network 列、CIDR 非法)跳过并计数,不再让整个库失效。
        let Ok(row) = row else {
            skipped_rows += 1;
            continue;
        };
        let Some(network) = get_csv(&headers, &row, &["network", "cidr", "ip"]) else {
            skipped_rows += 1;
            continue;
        };
        match Cidr::parse(&network) {
            Ok(network) => records.push(GeoIpRecord {
                network,
                country: get_csv(&headers, &row, &["country", "country_iso"]).unwrap_or_default(),
                region: get_csv(&headers, &row, &["region", "subdivision"]).unwrap_or_default(),
                city: get_csv(&headers, &row, &["city"]).unwrap_or_default(),
                asn: get_csv(&headers, &row, &["asn"]).unwrap_or_default(),
                as_org: get_csv(&headers, &row, &["as_org", "org", "organization"])
                    .unwrap_or_default(),
            }),
            Err(_) => skipped_rows += 1,
        }
    }
    Ok((records, skipped_rows))
}

fn load_json(path: &Path) -> std::result::Result<Vec<GeoIpRecord>, String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("jsonl"))
        .unwrap_or(false)
    {
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            records
                .push(record_from_json(&serde_json::from_str(line).map_err(
                    |error| format!("invalid GeoIP JSONL row: {error}"),
                )?)?);
        }
    } else {
        let value: Value = serde_json::from_str(&content).map_err(|error| error.to_string())?;
        let rows = value
            .as_array()
            .ok_or_else(|| "GeoIP JSON must be an array of objects".to_string())?;
        for row in rows {
            records.push(record_from_json(row)?);
        }
    }
    Ok(records)
}

fn record_from_json(value: &Value) -> std::result::Result<GeoIpRecord, String> {
    let network = json_string(value, &["network", "cidr", "ip"])
        .ok_or_else(|| "GeoIP JSON row missing network/cidr/ip".to_string())?;
    Ok(GeoIpRecord {
        network: Cidr::parse(&network)?,
        country: json_string(value, &["country", "country_iso"]).unwrap_or_default(),
        region: json_string(value, &["region", "subdivision"]).unwrap_or_default(),
        city: json_string(value, &["city"]).unwrap_or_default(),
        asn: json_string(value, &["asn"]).unwrap_or_default(),
        as_org: json_string(value, &["as_org", "org", "organization"]).unwrap_or_default(),
    })
}

fn get_csv(headers: &csv::StringRecord, row: &csv::StringRecord, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
            .and_then(|index| row.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn json_string(value: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        value.get(*name).and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_csv_geoip_lookup() {
        let root = crate::unique_test_dir("geoip");
        fs::create_dir_all(&root).unwrap();
        let csv = root.join("geo.csv");
        fs::write(
            &csv,
            "network,country,region,city,asn,as_org\n203.0.113.0/24,ZZ,Example,Test,64500,Example ASN\n",
        )
        .unwrap();

        let (db, errors) = GeoIpDb::load(Some(&csv));

        assert!(errors.is_empty());
        let hit = db.lookup("203.0.113.10").unwrap();
        assert_eq!(hit.country, "ZZ");
        assert_eq!(hit.asn, "64500");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bad_geoip_rows_are_skipped_but_database_loads() {
        let root = crate::unique_test_dir("geoip-bad");
        fs::create_dir_all(&root).unwrap();
        let csv = root.join("geo.csv");
        fs::write(
            &csv,
            "network,country,region,city,asn,as_org\nnot-a-cidr,ZZ,,,,\n198.51.100.0/24,YY,Other,City,64501,Other ASN\n,,,,,\n",
        )
        .unwrap();

        let (db, errors) = GeoIpDb::load(Some(&csv));

        // 好行继续可用,坏行跳过并通过 errors 管道汇总告警。
        assert_eq!(db.sources[0].records_loaded, 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("2 malformed GeoIP row"));
        let hit = db.lookup("198.51.100.10").unwrap();
        assert_eq!(hit.country, "YY");
        assert!(db.lookup("203.0.113.10").is_none());

        fs::remove_dir_all(root).unwrap();
    }
}
