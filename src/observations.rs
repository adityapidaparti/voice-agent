//! Signed, minimal operational observations and categorical answers.
//! Provenance is not proof of classification accuracy or business completion.
use crate::{contract::identifier, provider::verify_signature, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_PHASE_BODY: usize = 16 * 1024;
pub const MAX_PHASE_SEQUENCE: u16 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPhase {
    Ivr,
    Hold,
    Talking,
    AuthenticationRequired,
    DtmfRequired,
    DeclinedAi,
    UncertainMenu,
    ProhibitedAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseObservation {
    pub operation_id: String,
    pub call_id: String,
    pub intent_digest: String,
    pub sequence: u16,
    pub phase: ObservedPhase,
    pub observed_at: i64,
}

// The sender cannot choose the observation clock, include free text, or supply a call wrapper.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhasePayload {
    operation_id: String,
    call_id: String,
    intent_digest: String,
    sequence: u16,
    phase: ObservedPhase,
}

pub fn verify_phase(
    raw: &[u8],
    signature: &str,
    key: &[u8],
    now_ms: i64,
) -> Result<PhaseObservation> {
    if raw.len() > MAX_PHASE_BODY {
        return Err(Error::new("phase_body_too_large", 4));
    }
    let signed_at = verify_signature(raw, signature, key, now_ms)?;
    if now_ms.abs_diff(signed_at) > 30_000 {
        return Err(Error::new("stale_phase_observation", 4));
    }
    let body: PhasePayload = serde_json::from_slice(raw)?;
    if !valid_scope(
        &body.operation_id,
        &body.call_id,
        &body.intent_digest,
        body.sequence,
    ) {
        return Err(Error::new("invalid_phase_scope", 4));
    }
    Ok(PhaseObservation {
        operation_id: body.operation_id,
        call_id: body.call_id,
        intent_digest: body.intent_digest,
        sequence: body.sequence,
        phase: body.phase,
        // Future clock skew must not grant a longer hold/deadline window.
        observed_at: signed_at.min(now_ms) / 1000,
    })
}

/// This exact schema is part of the pinned LLM configuration. The provider's
/// args-only mode omits the call wrapper, including transcript and media URLs.
pub fn phase_tool(url: &str) -> Value {
    json!({
        "type": "custom",
        "name": "observe_phase",
        "description": "Report each IVR menu, entry to hold, conversation with a representative, or a safety boundary. Increment sequence from 1 for each new observation; never reuse it for changed evidence. Report authentication_required, dtmf_required, or declined_ai and end the call. Never send authentication data or conversation text.",
        "url": url,
        "method": "POST",
        "args_at_root": true,
        "max_retry": 0,
        "timeout_ms": 2000,
        "speak_during_execution": false,
        "speak_after_execution": false,
        "enable_typing_sound": false,
        "parameters": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "operation_id": {"type":"string", "const":"{{operation_id}}"},
                "call_id": {"type":"string", "const":"{{call_id}}"},
                "intent_digest": {"type":"string", "const":"{{intent_digest}}"},
                "sequence": {"type":"integer", "minimum":1, "maximum":128,
                    "description":"Monotonically increasing observation number within this call, starting at 1."},
                "phase": {"type":"string", "enum":["ivr","hold","talking","authentication_required","dtmf_required","declined_ai"],
                    "description":"The operational phase just observed; choose a safety boundary immediately if present."}
            },
            "required":["operation_id","call_id","intent_digest","sequence","phase"]
        }
    })
}

/// Native profile schema is separate so existing spoken-only published pins stay valid.
pub fn phase_tool_for(url: &str, profile: crate::contract::MenuNavigation) -> Value {
    let mut tool = phase_tool(url);
    if profile == crate::contract::MenuNavigation::ModelGuidedPublicMenu {
        tool["description"] = json!("Report each IVR menu, hold, conversation, or safety boundary with a new sequence. Report authentication_required, declined_ai, uncertain_menu, or prohibited_action and end. Report dtmf_required before a public routing digit only under the approved model_guided_public_menu profile; if the callback fails, end without pressing. Never send authentication data or conversation text.");
        tool["parameters"]["properties"]["phase"]["enum"] = json!([
            "ivr",
            "hold",
            "talking",
            "authentication_required",
            "dtmf_required",
            "declined_ai",
            "uncertain_menu",
            "prohibited_action"
        ]);
    }
    tool
}

fn valid_scope(operation_id: &str, call_id: &str, intent_digest: &str, sequence: u16) -> bool {
    identifier(operation_id)
        && identifier(call_id)
        && (1..=MAX_PHASE_SEQUENCE).contains(&sequence)
        && intent_digest.strip_prefix("sha256:").is_some_and(|d| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedStatus {
    Unknown,
    UnderReview,
    AwaitingDocuments,
    UnableToLocate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Receipt,
    ClaimForm,
    ReturnPolicy,
    Photos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextStep {
    Unknown,
    Wait,
    SubmitDocuments,
    ContactDirectly,
}

/// A model's categorical account of the answer; never an assertion of business success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedAnswer {
    pub status: ReportedStatus,
    pub required_documents: Vec<DocumentKind>,
    pub next_step: NextStep,
}
impl ReportedAnswer {
    pub fn validate(&self) -> Result<()> {
        if self.required_documents.len() > 4
            || self
                .required_documents
                .iter()
                .enumerate()
                .any(|(n, document)| self.required_documents[..n].contains(document))
        {
            return Err(Error::new("invalid_reported_documents", 4));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    UnverifiedModelReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerEvidence {
    pub evidence_ref: String,
    pub reported_at: i64,
    pub verification: Verification,
    pub answer: ReportedAnswer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportObservation {
    pub operation_id: String,
    pub call_id: String,
    pub intent_digest: String,
    pub sequence: u16,
    pub answer: ReportedAnswer,
    pub observed_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportPayload {
    operation_id: String,
    call_id: String,
    intent_digest: String,
    sequence: u16,
    answer: ReportedAnswer,
}

pub fn verify_report(
    raw: &[u8],
    signature: &str,
    key: &[u8],
    now_ms: i64,
) -> Result<ReportObservation> {
    if raw.len() > MAX_PHASE_BODY {
        return Err(Error::new("report_body_too_large", 4));
    }
    let signed_at = verify_signature(raw, signature, key, now_ms)?;
    if now_ms.abs_diff(signed_at) > 30_000 {
        return Err(Error::new("stale_answer_report", 4));
    }
    let body: ReportPayload = serde_json::from_slice(raw)?;
    if !valid_scope(
        &body.operation_id,
        &body.call_id,
        &body.intent_digest,
        body.sequence,
    ) {
        return Err(Error::new("invalid_report_scope", 4));
    }
    body.answer.validate()?;
    Ok(ReportObservation {
        operation_id: body.operation_id,
        call_id: body.call_id,
        intent_digest: body.intent_digest,
        sequence: body.sequence,
        answer: body.answer,
        observed_at: signed_at.min(now_ms) / 1000,
    })
}

/// A separate narrow callback captures useful results without fetching a retained transcript.
pub fn report_tool(url: &str) -> Value {
    let mut tool = phase_tool(url);
    tool["name"] = json!("report_answer");
    tool["description"] = json!("Before ending, report only these categorical answers that the representative actually gave. Use unknown or an empty document list when not observed; do not infer or invent facts. Increment the observation sequence for each changed report. This is an unverified model report, not confirmation of a claim or authentication. Never send conversation text, account identifiers, authentication data or other facts.");
    let properties = tool["parameters"]["properties"]
        .as_object_mut()
        .expect("fixed schema object");
    properties.remove("phase");
    properties.insert("answer".into(), json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "status": {"type":"string", "enum":["unknown","under_review","awaiting_documents","unable_to_locate"],
                "description":"Only the reported status; unknown if no clear answer was heard."},
            "required_documents": {"type":"array", "maxItems":4, "uniqueItems":true,
                "items":{"type":"string", "enum":["receipt","claim_form","return_policy","photos"]},
                "description":"Only document types the representative explicitly requested; empty if unobserved."},
            "next_step": {"type":"string", "enum":["unknown","wait","submit_documents","contact_directly"],
                "description":"Only the next step the representative stated; unknown if unobserved."}
        },
        "required":["status","required_documents","next_step"]
    }));
    tool["parameters"]["required"] = json!([
        "operation_id",
        "call_id",
        "intent_digest",
        "sequence",
        "answer"
    ]);
    tool
}

/// A provider-neutral menu-only plan, not a permission or an execution endpoint.
/// A future provider must bind it to the approved digest and reserve each attempt
/// durably before sending. The hosted Retell LLM cannot enforce this plan today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DtmfPlan {
    pub allowed_menu_digits: Vec<String>,
    pub max_presses: u8,
}
impl DtmfPlan {
    pub fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.max_presses)
            || self.allowed_menu_digits.is_empty()
            || self.allowed_menu_digits.len() > 10
            || self
                .allowed_menu_digits
                .iter()
                .any(|digit| digit.len() != 1 || !digit.as_bytes()[0].is_ascii_digit())
            || self
                .allowed_menu_digits
                .iter()
                .enumerate()
                .any(|(n, digit)| self.allowed_menu_digits[..n].contains(digit))
        {
            return Err(Error::new("invalid_menu_digit_plan", 4));
        }
        Ok(())
    }

    pub fn permits_menu_digit(&self, digit: &str, reserved_attempts: u8) -> bool {
        self.validate().is_ok()
            && reserved_attempts < self.max_presses
            && self
                .allowed_menu_digits
                .iter()
                .any(|allowed| allowed == digit)
    }

    /// Even a valid menu plan is unavailable on the pinned native LLM transport.
    pub fn require_retell_execution(&self) -> Result<()> {
        self.validate()?;
        Err(Error::new("retell_bounded_dtmf_unavailable", 4))
    }
}
