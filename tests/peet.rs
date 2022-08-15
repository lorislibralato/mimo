use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeetResponse {
    pub donate: String,
    pub ip: String,
    #[serde(rename = "http_version")]
    pub http_version: String,
    pub path: String,
    pub method: String,
    pub tls: Tls,
    pub http2: Http2,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tls {
    pub ciphers: Vec<String>,
    pub curves: Vec<String>,
    pub extensions: Vec<String>,
    pub points: Vec<String>,
    pub version: String,
    pub protocols: Vec<String>,
    pub versions: Vec<String>,
    pub ja3: String,
    #[serde(rename = "ja3_hash")]
    pub ja3_hash: String,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Http2 {
    #[serde(rename = "akamai_fingerprint")]
    pub akamai_fingerprint: String,
    #[serde(rename = "akamai_fingerprint_hash")]
    pub akamai_fingerprint_hash: String,
    #[serde(rename = "sent_frames")]
    pub sent_frames: Vec<SentFrame>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentFrame {
    #[serde(rename = "frame_type")]
    pub frame_type: String,
    pub length: i64,
    pub settings: Option<Vec<String>>,
    pub increment: Option<i64>,
    #[serde(rename = "stream_id")]
    pub stream_id: Option<i64>,
    #[serde(default)]
    pub headers: Vec<String>,
    pub flags: Option<Vec<String>>,
    pub priority: Option<Priority>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Priority {
    pub weight: i64,
    #[serde(rename = "depends_on")]
    pub depends_on: i64,
    pub exclusive: i64,
}
