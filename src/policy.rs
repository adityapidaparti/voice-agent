//! Operator-verified contacts and conservative complete rate bounds, independent of caller input.
use crate::{contract::*, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    pub work_system: String,
    pub destination: Destination,
    pub agent_id: String,
    pub agent_version: u32,
    #[serde(default)]
    pub menu_navigation: MenuNavigation,
    pub rate_ref: String,
    pub rate_cents_per_minute: u32,
    pub handoff_recipient_ref: String,
    pub handoff_endpoint_ref: String,
    pub consent_policy_ref: String,
    pub expires_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerPolicy {
    pub directory: Vec<DirectoryEntry>,
    pub daily_budget_cents: u32,
}
impl ControllerPolicy {
    pub fn validate(&self, now: i64) -> Result<()> {
        if self.directory.is_empty()
            || self.directory.len() > 64
            || self.daily_budget_cents == 0
            || self.daily_budget_cents > 2500
        {
            return Err(Error::new("invalid_controller_policy", 4));
        }
        for d in &self.directory {
            if !us_number(&d.destination.e164)
                || d.agent_version == 0
                || d.rate_cents_per_minute == 0
                || d.expires_at <= now
                || [
                    &d.work_system,
                    &d.destination.source_ref,
                    &d.destination.source_version,
                    &d.agent_id,
                    &d.rate_ref,
                    &d.handoff_recipient_ref,
                    &d.handoff_endpoint_ref,
                    &d.consent_policy_ref,
                ]
                .iter()
                .any(|v| !identifier(v))
            {
                return Err(Error::new("invalid_controller_policy", 4));
            }
        }
        Ok(())
    }
    pub fn authorize(&self, i: &Intent, now: i64) -> Result<()> {
        self.validate(now)?;
        if !self.directory.iter().any(|d| {
            d.work_system == i.work_item.system
                && d.destination.e164 == i.destination.e164
                && d.destination.source_ref == i.destination.source_ref
                && d.destination.source_version == i.destination.source_version
                && d.agent_id == i.agent_id
                && d.agent_version == i.agent_version
                && d.menu_navigation == i.menu_navigation
                && d.rate_ref == i.limits.rate_ref
                && d.rate_cents_per_minute == i.limits.rate_cents_per_minute
                && d.handoff_recipient_ref == i.handoff.recipient_ref
                && d.handoff_endpoint_ref == i.handoff.endpoint_ref
                && d.consent_policy_ref == i.consent_policy_ref
        }) {
            return Err(Error::new("unverified_directory_or_configuration", 4));
        }
        Ok(())
    }
}
