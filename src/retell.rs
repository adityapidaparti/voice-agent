//! Retell HTTPS transport. Constructors do not contact the vendor.
//! A submitted create is never retried; lookup and stop are separate operations.
use crate::contract::{hash, identifier, us_number, Event, MenuNavigation, Operation};
use crate::provider::{
    build_retell_request, normalize_authenticated_call_event, retell_llm_template_for,
    CreateOutcome, Provider, ProviderLookup,
};
use crate::{Error, Result};
use reqwest::blocking::Client;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_RESPONSE: u64 = 1_048_576;
const REQUEST_TIMEOUT_SECONDS: u64 = 2;
const MAX_LOOKUP_PAGES: usize = 3;
const RING_SECONDS: i64 = 30;
const STOP_MARGIN_SECONDS: i64 = 5;
/// Two configuration reads and one create, with headroom for local processing.
/// The controller must acquire an authoritative dispatch lease longer than this.
pub const MAX_DISPATCH_PREPARATION_SECONDS: i64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetellConfig {
    pub from_number: String,
    pub agent_id: String,
    pub agent_version: u32,
    pub llm_id: String,
    pub llm_version: u32,
    pub agent_snapshot_sha256: String,
    pub llm_snapshot_sha256: String,
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub menu_navigation: MenuNavigation,
}

fn path_identifier(value: &str) -> bool {
    identifier(value) && ![".", ".."].contains(&value)
}

impl RetellConfig {
    pub fn validate(&self) -> Result<()> {
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !us_number(&self.from_number)
            || !path_identifier(&self.agent_id)
            || !path_identifier(&self.llm_id)
            || !digest(&self.agent_snapshot_sha256)
            || !digest(&self.llm_snapshot_sha256)
        {
            return Err(Error::new("invalid_retell_configuration", 4));
        }
        if self.menu_navigation == MenuNavigation::ModelGuidedPublicMenu
            && self.webhook_url.is_none()
        {
            return Err(Error::new("native_menu_requires_signed_observations", 4));
        }
        if let Some(value) = &self.webhook_url {
            let url = Url::parse(value).map_err(|_| Error::new("invalid_retell_webhook_url", 4))?;
            let native_host_invalid = self.menu_navigation == MenuNavigation::ModelGuidedPublicMenu
                && !url.host_str().is_some_and(|host| {
                    let host = host.trim_end_matches('.');
                    host.contains('.')
                        && host != "localhost"
                        && !host.ends_with(".localhost")
                        && !host.ends_with(".local")
                        && !host.ends_with(".internal")
                        && host.trim_matches(['[', ']']).parse::<IpAddr>().is_err()
                });
            if native_host_invalid
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/v1/webhooks/retell"
            {
                return Err(Error::new("invalid_retell_webhook_url", 4));
            }
        }
        Ok(())
    }

    /// Hash the complete reviewed response, including unknown fields. New vendor
    /// fields or edited settings fail closed until the snapshot is reviewed again.
    pub fn validate_snapshots(&self, agent: &Value, llm: &Value) -> Result<()> {
        self.validate()?;
        if snapshot_digest(agent)? != self.agent_snapshot_sha256
            || snapshot_digest(llm)? != self.llm_snapshot_sha256
            || agent["agent_id"] != self.agent_id
            || agent["version"] != self.agent_version
            || agent["is_published"] != true
            || agent["is_transfer_agent"] == true
            || agent["response_engine"]
                != json!({"type":"retell-llm","llm_id":self.llm_id,"version":self.llm_version})
            || llm["llm_id"] != self.llm_id
            || llm["version"] != self.llm_version
            || llm["is_published"] != true
        {
            return Err(Error::new("retell_pinned_configuration_mismatch", 4));
        }
        let empty = |v: &Value| v.is_null() || v.as_array().is_some_and(Vec::is_empty);
        if agent["data_storage_setting"] != "basic_attributes_only"
            || !agent["data_storage_retention_days"]
                .as_u64()
                .is_some_and(|n| (1..=30).contains(&n))
            || agent["contact_memory_config"]["enable_read"] != false
            || agent["contact_memory_config"]["enable_update"] != false
            || agent["allow_user_dtmf"] != false
            || agent["reminder_max_count"] != 0
            || agent["voicemail_option"]["action"]["type"] != "hangup"
            || !empty(&agent["pre_session_tools"])
            || !empty(&agent["post_session_tools"])
            || !empty(&agent["post_call_analysis_data"])
            || agent["webhook_url"].as_str() != self.webhook_url.as_deref()
        {
            return Err(Error::new("retell_unsafe_agent_configuration", 4));
        }
        let template = retell_llm_template_for(self.menu_navigation);
        let mut tools = template["general_tools"]
            .as_array()
            .expect("static template tools")
            .clone();
        if let Some(url) = &self.webhook_url {
            let mut phase_url =
                Url::parse(url).map_err(|_| Error::new("invalid_retell_webhook_url", 4))?;
            phase_url.set_path("/v1/functions/observe");
            tools.push(crate::observations::phase_tool_for(
                phase_url.as_str(),
                self.menu_navigation,
            ));
            phase_url.set_path("/v1/functions/report");
            tools.push(crate::observations::report_tool(phase_url.as_str()));
        }
        if llm["general_prompt"] != template["general_prompt"]
            || llm["general_tools"] != Value::Array(tools)
            || !empty(&llm["knowledge_base_ids"])
            || !empty(&llm["mcps"])
            || !empty(&llm["states"])
            || !llm["starting_state"].is_null()
            || !llm["default_dynamic_variables"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        {
            return Err(Error::new("retell_unsafe_llm_configuration", 4));
        }
        Ok(())
    }
}

/// Canonical JSON objects use sorted keys; array order remains significant.
pub fn snapshot_digest(value: &Value) -> Result<String> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted: std::collections::BTreeMap<_, _> =
                    map.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    Ok(hash(&serde_json::to_vec(&canonical(value))?))
}

/// Reserve ringing, a bounded submission, and a stop margin separately from the
/// provider's connected-call duration. Never widen a shorter approved deadline.
pub fn bounded_duration_seconds(op: &Operation, now: i64, elapsed_seconds: i64) -> Result<u32> {
    let intent = op
        .intent
        .as_ref()
        .ok_or(Error::new("missing_frozen_intent", 4))?;
    let remaining = op
        .deadline
        .saturating_sub(now)
        .saturating_sub(elapsed_seconds)
        .saturating_sub(RING_SECONDS + STOP_MARGIN_SECONDS + REQUEST_TIMEOUT_SECONDS as i64);
    if elapsed_seconds < 0 || remaining < 60 || intent.limits.duration_seconds < 60 {
        return Err(Error::new("retell_insufficient_remaining_duration", 4));
    }
    Ok((remaining as u64).min(u64::from(intent.limits.duration_seconds)) as u32)
}

pub struct RetellProvider {
    config: RetellConfig,
    client: Client,
    base_url: String,
    secret: String,
}
impl RetellProvider {
    pub fn new(config: RetellConfig, secret: String) -> Result<Self> {
        if secret.len() < 24 || secret.len() > 512 || !secret.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::new("invalid_retell_credential", 4));
        }
        Self::build(config, "https://api.retellai.com".into(), secret)
    }

    /// Offline integration-test boundary: no caller-supplied credential is
    /// accepted, and a non-loopback URL cannot be selected.
    pub fn for_loopback_tests(config: RetellConfig, base_url: &str) -> Result<Self> {
        let url = Url::parse(base_url).map_err(|_| Error::new("invalid_test_provider_url", 4))?;
        let loopback = url
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if url.scheme() != "http"
            || !loopback
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::new("invalid_test_provider_url", 4));
        }
        Self::build(
            config,
            base_url.trim_end_matches('/').to_owned(),
            "synthetic-retell-test-credential".into(),
        )
    }

    fn build(config: RetellConfig, base_url: String, secret: String) -> Result<Self> {
        config.validate()?;
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
            .connect_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| Error::new("retell_client_unavailable", 6))?;
        Ok(Self {
            config,
            client,
            base_url,
            secret,
        })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.secret);
        if let Some(body) = payload {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|_| Error::new("retell_response_unknown", 6))?;
        let status = response.status();
        if response.content_length().is_some_and(|n| n > MAX_RESPONSE) {
            return Err(Error::new("retell_response_too_large", 6));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::new("retell_response_unknown", 6))?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err(Error::new("retell_response_too_large", 6));
        }
        Ok((status, bytes))
    }

    fn get_json(&self, path: &str) -> Result<Value> {
        let (status, bytes) = self.send(Method::GET, path, None)?;
        if !status.is_success() {
            return Err(Error::new("retell_read_failed", 6));
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::new("retell_invalid_response", 6))
    }

    /// Read-only pin check; useful during explicitly authorized deployment setup.
    pub fn check_configuration(&self) -> Result<()> {
        let agent = self.get_json(&format!(
            "/get-agent/{}?version={}",
            self.config.agent_id, self.config.agent_version
        ))?;
        let llm = self.get_json(&format!(
            "/get-retell-llm/{}?version={}",
            self.config.llm_id, self.config.llm_version
        ))?;
        self.config.validate_snapshots(&agent, &llm)
    }

    fn validate_call(&self, call: &CallRecord, op: &Operation) -> Result<()> {
        if !path_identifier(&call.call_id)
            || call.metadata.operation_id != op.id
            || call.metadata.intent_digest != op.digest
            || op.call_id.as_ref().is_some_and(|id| id != &call.call_id)
            || call.agent_id != self.config.agent_id
            || call.agent_version != self.config.agent_version
            || call.call_type != "phone_call"
            || call.direction != "outbound"
            || call.from_number != self.config.from_number
            || op
                .intent
                .as_ref()
                .is_some_and(|i| i.destination.e164 != call.to_number)
        {
            return Err(Error::new("event_mapping_conflict", 4));
        }
        Ok(())
    }

    fn events(&self, call: CallRecord, op: &Operation, now: i64) -> Result<Vec<Event>> {
        self.validate_call(&call, op)?;
        let mut kinds = Vec::new();
        if call.start_timestamp.is_some() {
            kinds.push("call_started");
        }
        if matches!(
            call.call_status.as_str(),
            "ended" | "error" | "not_connected"
        ) {
            if call.end_timestamp.is_some() {
                kinds.push("call_ended");
            }
            if call.end_timestamp.is_some()
                && call
                    .call_cost
                    .as_ref()
                    .is_some_and(|c| c.combined_cost.is_some())
            {
                kinds.push("call_analyzed");
            }
        } else if !matches!(call.call_status.as_str(), "registered" | "ongoing") {
            return Err(Error::new("retell_unknown_call_status", 6));
        }
        let mut events = Vec::new();
        for kind in kinds {
            let raw = serde_json::to_vec(&json!({"event":kind,"call":call}))?;
            let mut event = normalize_authenticated_call_event(&raw, now.saturating_mul(1000))?;
            // Polling may observe a later cumulative cost without a webhook
            // revision id. Distinct values are evidence, not a conflicting replay.
            if kind == "call_analyzed" {
                event.key = format!(
                    "retell_cost_{}",
                    hash(
                        format!("{}:{}:{:?}", op.id, event.call_id, event.actual_cost_cents)
                            .as_bytes()
                    )
                );
            }
            events.push(event);
        }
        Ok(events)
    }
}

#[derive(Serialize, Deserialize)]
struct Correlation {
    #[serde(default)]
    operation_id: String,
    #[serde(default)]
    intent_digest: String,
}
#[derive(Serialize, Deserialize)]
struct CallCost {
    combined_cost: Option<f64>,
}
/// Deliberately omit transcripts, recordings, model success and arbitrary data.
#[derive(Serialize, Deserialize)]
struct CallRecord {
    call_id: String,
    call_type: String,
    direction: String,
    from_number: String,
    to_number: String,
    agent_id: String,
    agent_version: u32,
    call_status: String,
    metadata: Correlation,
    #[serde(default)]
    start_timestamp: Option<i64>,
    #[serde(default)]
    end_timestamp: Option<i64>,
    #[serde(default)]
    disconnection_reason: Option<String>,
    #[serde(default)]
    call_cost: Option<CallCost>,
}
#[derive(Deserialize)]
struct CallPage {
    items: Vec<CallRecord>,
    has_more: bool,
    #[serde(default)]
    pagination_key: Option<String>,
}

impl Provider for RetellProvider {
    fn create(&mut self, op: &Operation, now: i64) -> CreateOutcome {
        let expires = op.intent.as_ref().map_or(now, |intent| intent.not_after);
        self.create_bounded(op, now, expires)
    }

    fn create_guarded(
        &mut self,
        op: &Operation,
        now: i64,
        authorization_expires_at: i64,
    ) -> CreateOutcome {
        self.create_bounded(op, now, authorization_expires_at)
    }

    fn lookup(&mut self, op: &Operation, now: i64) -> Result<Vec<Event>> {
        self.reconcile_call(op, now).map(|result| result.events)
    }

    fn reconcile(&mut self, op: &Operation, now: i64) -> Result<ProviderLookup> {
        self.reconcile_call(op, now)
    }

    fn stop(&mut self, op: &Operation, _now: i64) -> Result<()> {
        let id = op
            .call_id
            .as_ref()
            .filter(|s| path_identifier(s))
            .ok_or(Error::new("call_identity_unknown", 6))?;
        let (status, _) = self.send(Method::POST, &format!("/v2/stop-call/{id}"), None)?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::new("stop_outcome_unknown", 6))
        }
    }
}

impl RetellProvider {
    fn create_bounded(
        &mut self,
        op: &Operation,
        now: i64,
        authorization_expires_at: i64,
    ) -> CreateOutcome {
        let started = Instant::now();
        let Some(intent) = op.intent.as_ref() else {
            return CreateOutcome::Rejected;
        };
        if now >= authorization_expires_at
            || !op.attempt_consumed
            || op.submitted_at.is_none()
            || op.call_id.is_some()
            || op.stop_reason.is_some()
            || op.ai_stopped
            || op.all_legs_ended
            || intent.agent_id != self.config.agent_id
            || intent.agent_version != self.config.agent_version
            || intent.menu_navigation != self.config.menu_navigation
        {
            return CreateOutcome::Rejected;
        }
        let Ok(mut body) = build_retell_request(op, &self.config.from_number, now) else {
            return CreateOutcome::Rejected;
        };
        if bounded_duration_seconds(op, now, 0).is_err() || self.check_configuration().is_err() {
            // No dial request has been sent. The one consumed attempt stays used.
            return CreateOutcome::Rejected;
        }
        let elapsed = started
            .elapsed()
            .as_millis()
            .div_ceil(1000)
            .min(i64::MAX as u128) as i64;
        let Ok(duration) = bounded_duration_seconds(op, now, elapsed) else {
            return CreateOutcome::Rejected;
        };
        if now.saturating_add(elapsed) >= authorization_expires_at.min(intent.not_after)
            || elapsed >= MAX_DISPATCH_PREPARATION_SECONDS - REQUEST_TIMEOUT_SECONDS as i64
        {
            return CreateOutcome::Rejected;
        }
        body["agent_override"]["agent"]["max_call_duration_ms"] = json!(u64::from(duration) * 1000);
        body["agent_override"]["agent"]["ring_duration_ms"] = json!(RING_SECONDS * 1000);
        body["agent_override"]["agent"]["allow_user_dtmf"] = json!(false);
        body["agent_override"]["agent"]["webhook_url"] = json!(self.config.webhook_url);
        let send_elapsed = started
            .elapsed()
            .as_millis()
            .div_ceil(1000)
            .min(i64::MAX as u128) as i64;
        if now.saturating_add(send_elapsed) >= authorization_expires_at.min(intent.not_after)
            || send_elapsed >= MAX_DISPATCH_PREPARATION_SECONDS - REQUEST_TIMEOUT_SECONDS as i64
        {
            return CreateOutcome::Rejected;
        }
        let Ok(send_duration) = bounded_duration_seconds(op, now, send_elapsed) else {
            return CreateOutcome::Rejected;
        };
        body["agent_override"]["agent"]["max_call_duration_ms"] =
            json!(u64::from(send_duration) * 1000);
        if intent.menu_navigation != self.config.menu_navigation {
            return CreateOutcome::Rejected;
        }
        let Ok((status, bytes)) = self.send(Method::POST, "/v2/create-phone-call", Some(&body))
        else {
            return CreateOutcome::Unknown;
        };
        if matches!(status.as_u16(), 400 | 401 | 402 | 422 | 429) {
            return CreateOutcome::Rejected;
        }
        if status.as_u16() != 201 {
            return CreateOutcome::Unknown;
        }
        let Ok(call) = serde_json::from_slice::<CallRecord>(&bytes) else {
            return CreateOutcome::Unknown;
        };
        if self.validate_call(&call, op).is_err() {
            return CreateOutcome::Unknown;
        }
        CreateOutcome::Accepted(call.call_id)
    }
}

impl RetellProvider {
    fn reconciled_record(
        &self,
        call: CallRecord,
        op: &Operation,
        now: i64,
    ) -> Result<ProviderLookup> {
        let call_id = call.call_id.clone();
        let events = self.events(call, op, now)?;
        // Registration establishes identity, not connection or termination. Keep
        // the binding even before timestamps exist so a revoked ringing call can stop.
        Ok(ProviderLookup {
            call_id: Some(call_id),
            events,
        })
    }
    fn reconcile_call(&mut self, op: &Operation, now: i64) -> Result<ProviderLookup> {
        if let Some(id) = &op.call_id {
            if !path_identifier(id) {
                return Err(Error::new("invalid_event_envelope", 4));
            }
            let (status, bytes) = self.send(Method::GET, &format!("/v2/get-call/{id}"), None)?;
            if !status.is_success() {
                return Err(Error::new("retell_lookup_unresolved", 6));
            }
            let call = serde_json::from_slice(&bytes)
                .map_err(|_| Error::new("retell_invalid_response", 6))?;
            return self.reconciled_record(call, op, now);
        }
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut found: Option<CallRecord> = None;
        for _ in 0..MAX_LOOKUP_PAGES {
            let mut body = json!({"filter_criteria":{"agent":[{"agent_id":self.config.agent_id,"version":[self.config.agent_version]}],"metadata":[{"type":"string","key":"operation_id","value":op.id}]},"limit":100,"sort_order":"descending","include_total":false});
            if let Some(value) = cursor {
                body["pagination_key"] = Value::String(value);
            }
            let (status, bytes) = self.send(Method::POST, "/v3/list-calls", Some(&body))?;
            if !status.is_success() {
                return Err(Error::new("retell_lookup_unresolved", 6));
            }
            let page: CallPage = serde_json::from_slice(&bytes)
                .map_err(|_| Error::new("retell_invalid_response", 6))?;
            if page.items.len() > 100 {
                return Err(Error::new("retell_lookup_unresolved", 6));
            }
            for call in page.items {
                if call.metadata.operation_id != op.id {
                    continue;
                }
                self.validate_call(&call, op)?;
                if let Some(previous) = &found {
                    if previous.call_id != call.call_id {
                        return Err(Error::new("event_mapping_conflict", 4));
                    }
                    // Repeated records across pages must agree, not silently
                    // choose whichever response was delivered last.
                    if serde_json::to_vec(previous)? != serde_json::to_vec(&call)? {
                        return Err(Error::new("event_mapping_conflict", 4));
                    }
                } else {
                    found = Some(call);
                }
            }
            if !page.has_more {
                return found.map_or_else(
                    || {
                        Ok(ProviderLookup {
                            call_id: None,
                            events: vec![],
                        })
                    },
                    |call| self.reconciled_record(call, op, now),
                );
            }
            let next = page
                .pagination_key
                .filter(|s| !s.is_empty() && s.len() <= 4096)
                .ok_or(Error::new("retell_lookup_unresolved", 6))?;
            if !seen_cursors.insert(next.clone()) {
                return Err(Error::new("retell_lookup_unresolved", 6));
            }
            cursor = Some(next);
        }
        // A truncated listing cannot establish uniqueness, even if a match was found.
        Err(Error::new("retell_lookup_unresolved", 6))
    }
}
