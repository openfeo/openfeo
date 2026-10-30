// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The tokio side of the control plane (SPEC §6.2, §6.3, §5.3): publishing `Arc<World>`
//! generations over a `watch` channel, tracking health with wedge detection, and supervising
//! plain tokio tasks with restart backoff. Kept apart from `openfeo-world` so reconcilers can take
//! a `&World` without a dependency on tokio (ADR-0009).

#![forbid(unsafe_code)]

pub mod health;
pub mod supervise;
pub mod world;

pub use health::HealthTracker;
pub use supervise::Supervisor;
pub use world::{Publisher, WorldRx};
