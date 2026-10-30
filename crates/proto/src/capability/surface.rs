//! A surface's declaration of what it can present and signal; it references the Access approval surface profile and cannot widen it (C-18, X-3, X-13, X-36).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use super::name::CapabilityName;
use crate::data_class::DataClass;
use crate::data_class::Domain;
use crate::data_class::RetentionClass;
use crate::id::{DeviceId, SurfaceCapabilityId};
use crate::interaction_types::Modality;
use crate::interaction_types::SurfaceClass;
use crate::ontology::Instant;
use crate::ontology::OpaqueId;
use crate::ontology::PartyRef;
use crate::ontology::ProducedBy;
use crate::ontology::ProvenanceLabel;
use crate::ontology::RecordStatus;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;
use crate::task::common::{check_header, checked_record, wire_enum};

wire_enum!(
    /// The kind of surface.
    SurfaceKind {
        /// An app.
        App = "app",
        /// The web.
        Web = "web",
        /// A widget.
        Widget = "widget",
        /// The lock screen.
        LockScreen = "lock_screen",
        /// A control.
        Control = "control",
        /// The menu bar.
        MenuBar = "menu_bar",
        /// The tray.
        Tray = "tray",
        /// A Live Activity.
        LiveActivity = "live_activity",
        /// A Live Update.
        LiveUpdate = "live_update",
        /// A complication.
        Complication = "complication",
        /// A notification.
        Notification = "notification",
        /// A browser extension.
        BrowserExtension = "browser_extension",
        /// A car voice template.
        CarVoiceTemplate = "car_voice_template",
        /// A glasses display.
        GlassesDisplay = "glasses_display",
    }
);

wire_enum!(
    /// A signal a surface can report through Relay.
    Signal {
        /// Worn.
        Worn = "worn",
        /// Locked.
        Locked = "locked",
        /// Camera active.
        CameraActive = "camera_active",
        /// Driving.
        Driving = "driving",
        /// Charging.
        Charging = "charging",
        /// Online.
        Online = "online",
    }
);

fn check_size(value: &SizeBudget) -> Result<(), ContractViolation> {
    require(
        value.max_bytes.is_some()
            || value.max_chars.is_some()
            || value.binary_answer_only.is_some(),
        "size budget names a limit",
    )
}

checked_record!(
    /// What fits on the surface.
    #[derive(Eq)]
    pub struct SizeBudget via SizeBudgetWire = "SizeBudgetWire", check check_size {
        /// Bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_bytes: Option<NonZeroU32>,
        /// Characters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_chars: Option<NonZeroU32>,
        /// Only a yes or no answer fits.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binary_answer_only: Option<bool>,
    }
);

wire_enum!(
    /// The record type discriminator of a surface capability.
    SurfaceCapabilityType {
        /// A surface capability.
        SurfaceCapability = "SurfaceCapability",
    }
);

fn check_surface(value: &SurfaceCapability) -> Result<(), ContractViolation> {
    check_header(
        value.version,
        value.supersedes.is_some(),
        value.status,
        value.deleted_at.as_ref(),
        &value.data_class,
        value.retention_class,
    )?;
    value.domain.check()?;
    value.produced_by.check()?;
    require(
        !value.modalities.is_empty() && unique(&value.modalities),
        "modalities",
    )?;
    require(unique(&value.local_actions), "local actions are unique")?;
    require(unique(&value.signals), "signals are unique")?;
    if value.surface_class == SurfaceClass::VoiceCar {
        require(
            value.modalities.iter().all(|m| *m == Modality::Voice),
            "a car surface is voice only",
        )?;
    }
    Ok(())
}

checked_record!(
    /// A client or device surface's declaration (C-18).
    pub struct SurfaceCapability via SurfaceCapabilityWire = "SurfaceCapabilityWire", check check_surface {
        /// The record type.
        #[serde(rename = "type")]
        pub record_type: SurfaceCapabilityType,
        /// The record identifier.
        pub id: SurfaceCapabilityId,
        /// The owner.
        pub owner: PartyRef,
        /// Life areas and project.
        pub domain: Domain,
        /// The data class.
        pub data_class: DataClass,
        /// The retention class.
        pub retention_class: RetentionClass,
        /// The record's provenance.
        pub provenance: ProvenanceLabel,
        /// When the record was written.
        pub recorded_at: Instant,
        /// The record version.
        pub version: NonZeroU32,
        /// The privacy promise version the record was collected under (PV-19).
        pub promise_version: NonZeroU32,
        /// The version this one supersedes.
        #[serde(deserialize_with = "Option::deserialize")]
        pub supersedes: Option<SurfaceCapabilityId>,
        /// Record lifecycle.
        pub status: RecordStatus,
        /// When the record was deleted.
        #[serde(deserialize_with = "Option::deserialize")]
        pub deleted_at: Option<Instant>,
        /// Who produced the record.
        pub produced_by: ProducedBy,
        /// The device.
        pub device_id: DeviceId,
        /// The surface class.
        pub surface_class: SurfaceClass,
        /// The surface kind.
        pub surface_kind: SurfaceKind,
        /// Modalities.
        pub modalities: Vec<Modality>,
        /// What fits.
        pub size_budget: SizeBudget,
        /// Capabilities it performs locally.
        pub local_actions: Vec<CapabilityName>,
        /// Whether it can observe the screen.
        pub screen_observation: bool,
        /// Signals it can report.
        pub signals: Vec<Signal>,
        /// The Access approval surface profile.
        pub approval_surface_profile_ref: OpaqueId,
        /// When it was declared.
        pub declared_at: Instant,
    }
);
