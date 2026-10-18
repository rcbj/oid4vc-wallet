//! Embed `locales/` so a language is a catalog file plus a row in
//! `locales/catalogs.json`, which is the same layout iya-sts uses.

use std::fs;
use std::path::Path;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let locales = Path::new(&manifest).join("locales");
    println!("cargo:rerun-if-changed={}", locales.display());
    let mut out = String::new();
    out.push_str(&format!(
        "pub const INDEX_JSON: &str = include_str!(r\"{}/locales/catalogs.json\");\n",
        manifest
    ));
    out.push_str("pub fn catalog_json(namespace: &str, tag: &str) -> Option<&'static str> {\n");
    out.push_str("    match (namespace, tag) {\n");
    let entries = fs::read_dir(&locales).expect("locales directory");
    for entry in entries {
        let entry = entry.expect("locales entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let ns = entry.file_name().into_string().expect("namespace name");
        println!("cargo:rerun-if-changed={}", entry.path().display());
        for file in fs::read_dir(entry.path()).expect("namespace directory") {
            let file = file.expect("catalog file");
            let name = file.file_name().into_string().expect("catalog file name");
            let Some(tag) = name.strip_suffix(".json") else {
                continue;
            };
            println!("cargo:rerun-if-changed={}", file.path().display());
            out.push_str(&format!(
                "        (\"{ns}\", \"{tag}\") => Some(include_str!(r\"{path}\")),\n",
                path = file.path().display()
            ));
        }
    }
    out.push_str("        _ => None,\n    }\n}\n");
    let dest = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("locales_gen.rs");
    fs::write(dest, out).expect("write locales_gen.rs");
}
