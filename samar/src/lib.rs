// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Samar: system location override and location privacy layers.
//!
//! `policy` decides which location each app sees and which radio, media and local network data it
//! may read; `motion` and `sky` produce the simulated fix and satellite view; `geo` parses what
//! users paste (coordinates, map links, plus codes).

pub mod geo;
pub mod motion;
pub mod policy;
pub mod rng;
pub mod sky;
