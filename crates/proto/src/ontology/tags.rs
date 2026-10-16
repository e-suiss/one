//! The fixed wire values of canonical records: each concept's `type`, the live `status`, the forgotten `status`, `content_role`, Routine `authority` and the fixed retention classes (C-19, C-10, C-14, M-25, MF-22).

crate::const_tag!(
    /// `type: "Observation"`.
    ObservationType,
    "Observation"
);
crate::const_tag!(
    /// `type: "Episode"`.
    EpisodeType,
    "Episode"
);
crate::const_tag!(
    /// `type: "MemoryRecord"`.
    MemoryRecordType,
    "MemoryRecord"
);
crate::const_tag!(
    /// `type: "Goal"`.
    GoalType,
    "Goal"
);
crate::const_tag!(
    /// `type: "Routine"`.
    RoutineType,
    "Routine"
);
crate::const_tag!(
    /// `status: "active"`, the only status of a live Observation, Episode, Goal or Routine.
    Active,
    "active"
);
crate::const_tag!(
    /// `status: "forgotten"`, the status of a skeleton.
    Forgotten,
    "forgotten"
);
crate::const_tag!(
    /// `content_role: "data"`: observed content is data, never instruction.
    DataRole,
    "data"
);
crate::const_tag!(
    /// `authority: "NONE"`: a Routine never carries authority; this type has no other value (C-14).
    NoAuthority,
    "NONE"
);
crate::const_tag!(
    /// `retention_class: "one_memory"`.
    OneMemoryClass,
    "one_memory"
);
crate::const_tag!(
    /// `retention_class: "one_provider_trace"`.
    OneProviderTraceClass,
    "one_provider_trace"
);
