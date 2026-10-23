//! Generic canonical-workflow protocol; this is not a vendor-specific RP integration.
use crate::contract::{hash, identifier, WorkItem};
use crate::controller::{CanonicalWorkflow, Writeback, WritebackAck};
use crate::{Error, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

const MAX_BODY: usize = 65_536;
const MAX_TIMEOUT: Duration = Duration::from_secs(5);
const SYNTHETIC_TOKEN: &str = "synthetic-workflow-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStage {
    Preview,
    Reserve,
    Dispatch,
    Continue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateRequest {
    pub owner: String,
    pub operation_id: String,
    pub digest: String,
    pub work_item: WorkItem,
    pub policy_gate_ref: String,
    pub purpose_digest: String,
    pub stage: GateStage,
    pub reservation_id: Option<String>,
}
impl GateRequest {
    /// Hex SHA-256 over this versioned typed JSON representation, including nulls.
    pub fn request_digest(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub fn idempotency_key(&self) -> Result<String> {
        Ok(format!(
            "voice_{}",
            hash(&serde_json::to_vec(&(
                &self.operation_id,
                &self.digest,
                self.stage,
            ))?)
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateDecision {
    pub request_digest: String,
    pub allowed: bool,
    pub expires_at: i64,
    pub reservation_id: Option<String>,
}
impl GateDecision {
    pub fn validate(&self, request: &GateRequest, now: i64) -> Result<()> {
        if self.request_digest != request.request_digest()? {
            return Err(Error::new("workflow_decision_mismatch", 4));
        }
        if !self.allowed {
            return Err(Error::new("workflow_authority_denied", 4));
        }
        if self.expires_at <= now || self.expires_at > now.saturating_add(60) {
            return Err(Error::new("workflow_decision_stale", 4));
        }
        if self
            .reservation_id
            .as_ref()
            .is_some_and(|id| !identifier(id))
            || (request.stage != GateStage::Preview && self.reservation_id.is_none())
        {
            return Err(Error::new("workflow_reservation_required", 4));
        }
        if request
            .reservation_id
            .as_ref()
            .is_some_and(|id| self.reservation_id.as_ref() != Some(id))
        {
            return Err(Error::new("workflow_reservation_mismatch", 4));
        }
        Ok(())
    }
}

pub trait WorkflowAuthority: Send {
    fn authorize(&mut self, request: &GateRequest, now: i64) -> Result<GateDecision>;
}

/// No environment variables, credential discovery, automatic retry or raw-body logging.
pub struct HttpWorkflow {
    client: Client,
    base: Url,
    authorization: HeaderValue,
}
impl HttpWorkflow {
    /// The caller supplies an authorized service origin and separately obtained credential.
    /// Construction performs no request. Production transport always verifies TLS.
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self> {
        Self::build(base_url, bearer_token, MAX_TIMEOUT, false)
    }

    /// Explicit offline-test escape hatch: literal loopback HTTP and a fixed synthetic token.
    pub fn for_loopback_tests(base_url: &str, timeout: Duration) -> Result<Self> {
        Self::build(base_url, SYNTHETIC_TOKEN.into(), timeout, true)
    }

    fn build(base_url: &str, token: String, timeout: Duration, loopback: bool) -> Result<Self> {
        let base = Url::parse(base_url).map_err(|_| Error::new("invalid_workflow_origin", 2))?;
        if base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(Error::new("invalid_workflow_origin", 2));
        }
        if loopback {
            let host = base.host_str().unwrap_or("").trim_matches(['[', ']']);
            if base.scheme() != "http" || !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
                return Err(Error::new("workflow_test_requires_literal_loopback", 4));
            }
        } else if base.scheme() != "https" {
            return Err(Error::new("workflow_requires_https", 4));
        }
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
            || timeout.is_zero()
            || timeout > MAX_TIMEOUT
        {
            return Err(Error::new("invalid_workflow_configuration", 2));
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::new("invalid_workflow_configuration", 2))?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(3)))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .https_only(!loopback)
            .build()
            .map_err(|_| Error::new("workflow_client_unavailable", 6))?;
        Ok(Self {
            client,
            base,
            authorization,
        })
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(path);
        url
    }

    fn body<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_BODY {
            return Err(Error::new("workflow_request_too_large", 4));
        }
        Ok(bytes)
    }

    fn read<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T> {
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY as u64)
        {
            return Err(Error::new("workflow_response_too_large", 6));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::new("workflow_response_unknown", 6))?;
        if bytes.len() > MAX_BODY {
            return Err(Error::new("workflow_response_too_large", 6));
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::new("workflow_response_invalid", 6))
    }
}

impl WorkflowAuthority for HttpWorkflow {
    fn authorize(&mut self, request: &GateRequest, now: i64) -> Result<GateDecision> {
        let response = self
            .client
            .post(self.endpoint("/v1/voice/authorize"))
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", request.idempotency_key()?)
            .body(Self::body(request)?)
            .send()
            .map_err(|_| Error::new("workflow_response_unknown", 6))?;
        if response.status() != StatusCode::OK {
            return Err(Error::new("workflow_authority_unavailable", 6));
        }
        let decision: GateDecision = Self::read(response)?;
        decision.validate(request, now)?;
        Ok(decision)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultAcknowledgement {
    operation_id: String,
    result_version: u32,
    status: AcknowledgementStatus,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcknowledgementStatus {
    Applied,
    AlreadyApplied,
}
impl CanonicalWorkflow for HttpWorkflow {
    fn publish(&mut self, message: &Writeback) -> Result<WritebackAck> {
        if !identifier(&message.operation_id)
            || [".", ".."].contains(&message.operation_id.as_str())
            || !identifier(&message.work_item.version)
            || message.result_version == 0
            || message.result.operation_id != message.operation_id
            || message.result.result_version != message.result_version
            || message.result.work_item != message.work_item
        {
            return Err(Error::new("invalid_workflow_writeback", 4));
        }
        let response = self
            .client
            .put(self.endpoint(&format!(
                "/v1/voice/results/{}/{}",
                message.operation_id, message.result_version
            )))
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(IF_MATCH, format!("\"{}\"", message.work_item.version))
            .body(Self::body(message)?)
            .send()
            .map_err(|_| Error::new("workflow_response_unknown", 6))?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(WritebackAck::Conflict);
        }
        if response.status() != StatusCode::OK && response.status() != StatusCode::CREATED {
            return Err(Error::new("workflow_writeback_unavailable", 6));
        }
        let acknowledgement: ResultAcknowledgement = Self::read(response)?;
        if acknowledgement.operation_id != message.operation_id
            || acknowledgement.result_version != message.result_version
        {
            return Err(Error::new("workflow_acknowledgement_mismatch", 6));
        }
        Ok(match acknowledgement.status {
            AcknowledgementStatus::Applied => WritebackAck::Applied,
            AcknowledgementStatus::AlreadyApplied => WritebackAck::AlreadyApplied,
        })
    }
}
