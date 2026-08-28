use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct DiscoveryResult {
    pub middleware: Vec<MiddlewareRow>,
    pub web_roots: Vec<WebRootRow>,
    pub logs: Vec<DiscoveredLogRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MiddlewareRow {
    pub kind: String,
    pub source: String,
    pub evidence: String,
    pub confidence: u8,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebRootRow {
    pub path: String,
    pub source: String,
    pub middleware: String,
    pub priority: u8,
    pub exists: bool,
    pub readable: bool,
    pub notes: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredLogRow {
    pub path: String,
    pub source: String,
    pub middleware: String,
    pub priority: u8,
    pub exists: bool,
    pub notes: String,
    pub evidence: String,
}
