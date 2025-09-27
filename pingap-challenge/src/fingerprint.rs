// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the result of a fingerprint score calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreResult {
    /// The final calculated score.
    pub score: i32,
    /// A list of reasons for any score deductions.
    pub reasons: Vec<String>,
}

/// The top-level structure representing a complete browser fingerprint.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    /// The unique identifier for the visitor.
    pub visitor_id: String,
    /// A collection of all fingerprint components.
    pub components: Components,
    /// The version of the fingerprinting library.
    pub version: String,
}

/// A set of flags to control which fingerprint components are included in the score calculation.
/// Each field corresponds to a component; `true` enables its check.
pub struct CalculateFlags {
    pub fonts: bool,
    // pub audio: bool,
    pub screen_frame: bool,
    pub canvas: bool,
    pub device_memory: bool,
    pub screen_resolution: bool,
    pub hardware_concurrency: bool,
    pub session_storage: bool,
    pub local_storage: bool,
    pub indexed_db: bool,
    pub platform: bool,
    pub plugins: bool,
    pub vendor: bool,
    pub vendor_flavors: bool,
    pub cookies_enabled: bool,
    pub math: bool,
    pub pdf_viewer_enabled: bool,
    pub web_gl_basics: bool,
    pub web_gl_extensions: bool,
}

impl Default for CalculateFlags {
    fn default() -> Self {
        Self {
            fonts: true,
            // audio: true,
            screen_frame: true,
            canvas: true,
            device_memory: true,
            screen_resolution: true,
            hardware_concurrency: true,
            session_storage: true,
            local_storage: true,
            indexed_db: true,
            platform: true,
            plugins: true,
            vendor: true,
            vendor_flavors: true,
            cookies_enabled: true,
            math: true,
            pdf_viewer_enabled: true,
            web_gl_basics: true,
            web_gl_extensions: true,
        }
    }
}

/// Helper function to apply a penalty and record the reason based on a component's state.
/// This is a generic abstraction for scoring logic to avoid repetitive code in the main function.
///
/// # Arguments
/// * `result` - A mutable reference to the `ScoreResult` to update the score and reasons.
/// * `flag` - A boolean flag that controls whether this check is executed.
/// * `component` - An `Option` containing the fingerprint component data.
/// * `check` - A closure that defines how to validate the component if it exists, returning a penalty and reason if invalid.
/// * `absent_reason` - The penalty and reason to apply if the component is absent (`None`).
fn apply_penalty_with_reason<T, F>(
    result: &mut ScoreResult,
    flag: bool,
    component: Option<&T>,
    check: F,
    absent_reason: (i32, &'static str),
) where
    F: FnOnce(&T) -> Option<(i32, &'static str)>,
{
    // If the corresponding flag is false, skip this check.
    if !flag {
        return;
    }

    if let Some(value) = component {
        // If the component exists, execute the `check` closure for detailed validation.
        if let Some((penalty, reason)) = check(value) {
            // If the check returns `Some`, a penalty is warranted; update the score and reasons.
            result.score -= penalty;
            result.reasons.push(reason.to_string());
        }
    } else {
        // If the component is absent (`None`), apply the predefined penalty and reason directly.
        let (penalty, reason) = absent_reason;
        result.score -= penalty;
        result.reasons.push(reason.to_string());
    }
}

impl Fingerprint {
    /// Calculates a confidence score for the browser fingerprint.
    /// The score starts at 100, and points are deducted based on inconsistencies or anomalies in the fingerprint data.
    pub fn calculate_score(&self, flags: &CalculateFlags) -> ScoreResult {
        // Initialize the score result.
        let mut result = ScoreResult {
            score: 100,
            reasons: vec![],
        };
        let c = &self.components;

        // --- Simple value checks ---
        apply_penalty_with_reason(
            &mut result,
            flags.fonts,
            c.fonts.as_ref(),
            |v| {
                if v.value.len() < 3 {
                    Some((10, "system fonts is too few"))
                } else {
                    None
                }
            },
            (20, "cannot get fonts information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.canvas,
            c.canvas.as_ref(),
            |v| {
                if v.value.geometry.is_empty() {
                    Some((15, "Canvas geometry is empty"))
                } else {
                    None
                }
            },
            (15, "cannot get Canvas fingerprint"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.platform,
            c.platform.as_ref(),
            |v| {
                if v.value.is_empty() {
                    Some((10, "platform information is empty"))
                } else {
                    None
                }
            },
            (10, "cannot get platform information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.vendor,
            c.vendor.as_ref(),
            |v| {
                if v.value.is_empty() {
                    Some((10, "browser vendor information is empty"))
                } else {
                    None
                }
            },
            (10, "cannot get browser vendor information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.vendor_flavors,
            c.vendor_flavors.as_ref(),
            |v| {
                if v.value.is_empty() {
                    Some((10, "browser features information is empty"))
                } else {
                    None
                }
            },
            (10, "cannot get browser features information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.plugins,
            c.plugins.as_ref(),
            |v| {
                if v.value.len() < 5 {
                    Some((10, "browser plugins is too few"))
                } else {
                    None
                }
            },
            (10, "cannot get browser plugins information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.math,
            c.math.as_ref(),
            |v| {
                if v.value.len() < 5 {
                    Some((10, "Math information is incomplete"))
                } else {
                    None
                }
            },
            (10, "cannot get Math information"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.hardware_concurrency,
            c.hardware_concurrency.as_ref(),
            |v| {
                if v.value < 2 {
                    Some((10, "CPU cores is too low"))
                } else {
                    None
                }
            },
            (10, "cannot get CPU cores"),
        );

        // --- Boolean checks ---
        apply_penalty_with_reason(
            &mut result,
            flags.session_storage,
            c.session_storage.as_ref(),
            |v| {
                if !v.value {
                    Some((10, "browser does not support session storage"))
                } else {
                    None
                }
            },
            (10, "cannot detect SessionStorage support"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.local_storage,
            c.local_storage.as_ref(),
            |v| {
                if !v.value {
                    Some((10, "browser does not support local storage"))
                } else {
                    None
                }
            },
            (10, "cannot detect LocalStorage support"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.indexed_db,
            c.indexed_db.as_ref(),
            |v| {
                if !v.value {
                    Some((10, "browser does not support IndexedDB"))
                } else {
                    None
                }
            },
            (10, "cannot detect IndexedDB support"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.cookies_enabled,
            c.cookies_enabled.as_ref(),
            |v| {
                if !v.value {
                    Some((10, "browser disabled Cookie"))
                } else {
                    None
                }
            },
            (10, "cannot detect Cookie is enabled"),
        );
        apply_penalty_with_reason(
            &mut result,
            flags.pdf_viewer_enabled,
            c.pdf_viewer_enabled.as_ref(),
            |v| {
                if !v.value {
                    Some((10, "browser does not support PDF viewer"))
                } else {
                    None
                }
            },
            (10, "cannot detect PDF viewer status"),
        );

        // --- Complex checks with multiple conditions ---
        // safari audio fingerprint is not reliable
        // apply_penalty_with_reason(
        //     &mut result,
        //     flags.audio,
        //     c.audio.as_ref(),
        //     |audio| {
        //         let v = audio.value;
        //         if [-1.0, -2.0, -3.0, -4.0].contains(&v) {
        //             Some((40, "audio is invalid"))
        //         } else if v.fract() == 0.0 {
        //             Some((25, "audio is integer, may be tampered"))
        //         } else {
        //             let s = v.to_string();
        //             let decimal_part = s.split('.').nth(1).unwrap_or("");
        //             if decimal_part.len() < 5 {
        //                 Some((20, "audio precision is not enough"))
        //             } else {
        //                 None
        //             }
        //         }
        //     },
        //     (25, "cannot get audio fingerprint"),
        // );

        apply_penalty_with_reason(
            &mut result,
            flags.screen_frame,
            c.screen_frame.as_ref(),
            |frame| match frame.value.as_deref() {
                Some(v) if v.len() != 4 || v.iter().sum::<i64>() == 0 => {
                    Some((10, "screen available space data is abnormal"))
                },
                None => Some((10, "screen available space data is missing")),
                _ => None,
            },
            (10, "cannot get screen available space information"),
        );

        apply_penalty_with_reason(
            &mut result,
            flags.device_memory,
            c.device_memory.as_ref(),
            |mem| {
                mem.value.and_then(|v| {
                    if v <= 2 {
                        Some((10, "device memory(RAM) is too low"))
                    } else {
                        None
                    }
                })
            },
            (10, "cannot get device memory information"),
        );

        apply_penalty_with_reason(
            &mut result,
            flags.screen_resolution,
            c.screen_resolution.as_ref(),
            |res| match res.value.as_deref() {
                Some(v) if v.len() < 2 || v[0] < 1024 || v[1] < 768 => {
                    Some((10, "screen resolution is too low or abnormal"))
                },
                None => Some((10, "screen resolution data is missing")),
                _ => None,
            },
            (10, "cannot get screen resolution information"),
        );

        apply_penalty_with_reason(
            &mut result,
            flags.web_gl_basics,
            c.web_gl_basics.as_ref(),
            |basics| {
                let renderer =
                    basics.value.renderer_unmasked.as_deref().unwrap_or("");
                if renderer.is_empty() {
                    return Some((40, "WebGL renderer information is empty"));
                }
                let lower_renderer = renderer.to_lowercase();
                if lower_renderer.contains("swiftshader")
                    || lower_renderer.contains("software renderer")
                {
                    return Some((
                        40,
                        "use software simulation rendering, not real hardware",
                    ));
                }
                None
            },
            (40, "cannot get WebGL basic information"),
        );

        apply_penalty_with_reason(
            &mut result,
            flags.web_gl_extensions,
            c.web_gl_extensions.as_ref(),
            |ext| match ext.value.extensions.as_deref() {
                Some([]) => Some((30, "WebGL extensions list is empty")),
                Some(e) if e.len() < 15 => {
                    Some((20, "WebGL extensions is too few"))
                },
                None => Some((30, "WebGL extensions list is missing")),
                _ => None,
            },
            (30, "cannot get WebGL extensions information"),
        );

        result
    }
}

/// Holds all the individual fingerprinting components.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Components {
    pub fonts: Option<Fonts>,
    pub audio: Option<Audio>,
    pub screen_frame: Option<ScreenFrame>,
    pub canvas: Option<Canvas>,
    pub device_memory: Option<DeviceMemory>,
    pub screen_resolution: Option<ScreenResolution>,
    pub hardware_concurrency: Option<HardwareConcurrency>,
    pub session_storage: Option<SessionStorage>,
    pub local_storage: Option<LocalStorage>,
    #[serde(rename = "indexedDB")]
    pub indexed_db: Option<IndexedDb>,
    pub platform: Option<Platform>,
    pub plugins: Option<Plugins>,
    pub vendor: Option<Vendor>,
    pub vendor_flavors: Option<VendorFlavors>,
    pub cookies_enabled: Option<CookiesEnabled>,
    pub math: Option<Math>,
    pub pdf_viewer_enabled: Option<PdfViewerEnabled>,
    pub web_gl_basics: Option<WebGlBasics>,
    pub web_gl_extensions: Option<WebGlExtensions>,
}

/// System fonts component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fonts {
    pub value: Vec<String>,
    pub duration: i64,
}

/// Audio fingerprint component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Audio {
    pub value: f64,
    pub duration: i64,
}

/// Available screen space (excluding OS toolbars).
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenFrame {
    pub value: Option<Vec<i64>>,
    pub duration: i64,
}

/// Value part of the Canvas component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanvasValue {
    pub winding: bool,
    pub geometry: String,
    pub text: String,
}

/// Canvas fingerprint component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Canvas {
    pub value: CanvasValue,
    pub duration: i64,
}

/// Device memory (RAM) component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMemory {
    /// Device memory in Gigabytes.
    pub value: Option<i64>,
    pub duration: i64,
}

/// Screen resolution component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenResolution {
    pub value: Option<Vec<i64>>,
    pub duration: i64,
}

/// CPU concurrency component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareConcurrency {
    /// Number of logical CPU cores.
    pub value: i64,
    pub duration: i64,
}

/// SessionStorage support component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStorage {
    pub value: bool,
    pub duration: i64,
}

/// LocalStorage support component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalStorage {
    pub value: bool,
    pub duration: i64,
}

/// IndexedDB support component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedDb {
    pub value: bool,
    pub duration: i64,
}

/// Platform (OS) component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub value: String,
    pub duration: i64,
}

/// Browser plugins component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plugins {
    pub value: Vec<PluginValue>,
    pub duration: i64,
}

/// Details of a single browser plugin.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginValue {
    pub name: String,
    pub description: String,
    pub mime_types: Vec<MimeType>,
}

/// Details of a MIME type supported by a plugin.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MimeType {
    #[serde(rename = "type")]
    pub type_field: String,
    pub suffixes: String,
}

/// Browser vendor component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vendor {
    pub value: String,
    pub duration: i64,
}

/// Browser-specific features or "flavors".
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorFlavors {
    pub value: Vec<String>,
    pub duration: i64,
}

/// Cookie support component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookiesEnabled {
    pub value: bool,
    pub duration: i64,
}

/// Math constants fingerprint component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Math {
    pub value: HashMap<String, f64>,
    pub duration: i64,
}

/// PDF viewer support component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfViewerEnabled {
    pub value: bool,
    pub duration: i64,
}

/// Basic WebGL information component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebGlBasics {
    pub value: WebGlBasicsValue,
    pub duration: i64,
}

/// Value part of the WebGL basics component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebGlBasicsValue {
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub vendor_unmasked: Option<String>,
    pub renderer: Option<String>,
    pub renderer_unmasked: Option<String>,
    pub shading_language_version: Option<String>,
}

/// WebGL extensions component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebGlExtensions {
    pub value: WebGlExtensionValue,
    pub duration: i64,
}

/// Value part of the WebGL extensions component.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebGlExtensionValue {
    pub context_attributes: Option<Vec<String>>,
    pub parameters: Option<Vec<String>>,
    pub shader_precisions: Option<Vec<String>>,
    pub extensions: Option<Vec<String>>,
    pub extension_parameters: Option<Vec<String>>,
    pub unsupported_extensions: Option<Vec<String>>,
}
