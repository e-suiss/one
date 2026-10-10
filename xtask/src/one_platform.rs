//! `platform-policy`: Android permissions and iOS background modes and entitlements stay in their allowlists, no app drives other apps through accessibility, and nothing requests Full Disk Access (T-30 (1), T-22, CP-13, X-41).

use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::read;

const ANDROID: &str = "conformance/platform/android.toml";
const APPLE: &str = "conformance/platform/apple.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Android {
    #[serde(default)]
    pub(crate) permission: Vec<Entry>,
    pub(crate) forbidden: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Apple {
    #[serde(default)]
    pub(crate) background_mode: Vec<Entry>,
    #[serde(default)]
    pub(crate) entitlement: Vec<Entry>,
    pub(crate) forbidden: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) reason: String,
}

fn attr_values<'a>(xml: &'a str, element: &str, attr: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for chunk in xml.split(&format!("<{element}")).skip(1) {
        let tag = chunk.split('>').next().unwrap_or_default();
        if let Some(rest) = tag.split(&format!("{attr}=\"")).nth(1)
            && let Some(value) = rest.split('"').next()
        {
            out.push(value);
        }
    }
    out
}

pub(crate) fn manifest_findings(xml: &str, policy: &Android) -> Vec<String> {
    let mut out = Vec::new();
    for name in attr_values(xml, "uses-permission", "android:name") {
        if !policy.permission.iter().any(|p| p.name == name) {
            out.push(format!("permission `{name}` is not in {ANDROID}"));
        }
    }
    for marker in &policy.forbidden {
        if xml.contains(marker.as_str()) {
            out.push(format!("`{marker}` is forbidden"));
        }
    }
    out
}

fn plist_array(xml: &str, key: &str) -> Vec<String> {
    let Some(after) = xml.split(&format!("<key>{key}</key>")).nth(1) else {
        return Vec::new();
    };
    let array = after.split("</array>").next().unwrap_or_default();
    array
        .split("<string>")
        .skip(1)
        .filter_map(|s| s.split("</string>").next())
        .map(|s| s.trim().to_owned())
        .collect()
}

fn plist_keys(xml: &str) -> Vec<String> {
    xml.split("<key>")
        .skip(1)
        .filter_map(|s| s.split("</key>").next())
        .map(|s| s.trim().to_owned())
        .collect()
}

pub(crate) fn info_plist_findings(xml: &str, policy: &Apple) -> Vec<String> {
    let mut out: Vec<String> = plist_array(xml, "UIBackgroundModes")
        .into_iter()
        .filter(|m| !policy.background_mode.iter().any(|e| &e.name == m))
        .map(|m| format!("background mode `{m}` is not in {APPLE}"))
        .collect();
    out.extend(forbidden(xml, &policy.forbidden));
    out
}

pub(crate) fn entitlement_findings(xml: &str, policy: &Apple) -> Vec<String> {
    let mut out: Vec<String> = plist_keys(xml)
        .into_iter()
        .filter(|k| !policy.entitlement.iter().any(|e| &e.name == k))
        .map(|k| format!("entitlement `{k}` is not in {APPLE}"))
        .collect();
    out.extend(forbidden(xml, &policy.forbidden));
    out
}

fn forbidden(xml: &str, markers: &[String]) -> Vec<String> {
    markers
        .iter()
        .filter(|m| xml.contains(m.as_str()))
        .map(|m| format!("`{m}` is forbidden"))
        .collect()
}

fn reasons(entries: &[Entry], file: &str) -> Vec<Violation> {
    entries
        .iter()
        .filter(|e| e.reason.trim().is_empty())
        .map(|e| v("T-30", file, format!("`{}` has no reason", e.name)))
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let android: Android =
        toml::from_str(&read_opt(root, ANDROID)?.ok_or_else(|| format!("{ANDROID} is missing"))?)
            .map_err(|e| format!("{ANDROID}: {e}"))?;
    let apple: Apple =
        toml::from_str(&read_opt(root, APPLE)?.ok_or_else(|| format!("{APPLE} is missing"))?)
            .map_err(|e| format!("{APPLE}: {e}"))?;
    let mut out = reasons(&android.permission, ANDROID);
    out.extend(reasons(&apple.background_mode, APPLE));
    out.extend(reasons(&apple.entitlement, APPLE));
    for file in repo_files(root)?.iter().filter(|f| f.starts_with("apps/")) {
        let name = file.rsplit('/').next().unwrap_or_default();
        let found = if name == "AndroidManifest.xml" {
            manifest_findings(&read(&root.join(file))?, &android)
        } else if name == "Info.plist" {
            info_plist_findings(&read(&root.join(file))?, &apple)
        } else if name.ends_with(".entitlements") {
            entitlement_findings(&read(&root.join(file))?, &apple)
        } else {
            continue;
        };
        out.extend(found.into_iter().map(|m| v("T-30", file.clone(), m)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn android() -> Android {
        Android {
            permission: vec![Entry {
                name: "android.permission.INTERNET".into(),
                reason: "sync".into(),
            }],
            forbidden: vec!["android.accessibilityservice.AccessibilityService".into()],
        }
    }

    fn apple() -> Apple {
        Apple {
            background_mode: vec![Entry {
                name: "processing".into(),
                reason: "BGTaskScheduler".into(),
            }],
            entitlement: Vec::new(),
            forbidden: vec!["SystemPolicyAllFiles".into()],
        }
    }

    #[test]
    fn t_30_unlisted_permission_and_accessibility_service_are_rejected() {
        let xml = r#"<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<action android:name="android.accessibilityservice.AccessibilityService"/>"#;
        assert_eq!(manifest_findings(xml, &android()).len(), 2);
    }

    #[test]
    fn t_30_unlisted_background_mode_and_entitlement_are_rejected() {
        let plist = "<key>UIBackgroundModes</key><array><string>processing</string><string>audio</string></array>";
        assert_eq!(info_plist_findings(plist, &apple()).len(), 1);
        let ent = "<key>com.apple.developer.healthkit</key><true/>";
        assert_eq!(entitlement_findings(ent, &apple()).len(), 1);
    }
}
