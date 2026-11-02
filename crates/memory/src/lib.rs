//! The memory component (M-6, M-24, M-25, M-30): records are written along the M-15 paths, changed only by new versions, shown as a data block, corrected, set aside or permanently forgotten by the user, retrieved through the fixed eight-step pipeline and exported whole; the domain is pure, the ports name storage and search, and the adapter keeps every row sealed.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
