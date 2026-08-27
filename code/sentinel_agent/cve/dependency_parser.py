import json
import re
from collections import defaultdict

INCLUDE_PATTERN = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.MULTILINE)
IGNORED_HEADERS = []

# Alias dictionary: map headers / CMake names / package names to normalized component names.
KNOWN_COMPONENTS = {
    "openssl": {
        "headers": ["openssl/ssl.h", "openssl/crypto.h", "openssl/evp.h", "openssl/bio.h"],
        "keywords": ["openssl", "ssl", "crypto", "openssl::ssl", "openssl::crypto"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "openssl",
        "nvd_products": [("openssl", "openssl")],
    },
    "libpng": {
        "headers": ["png.h"],
        "keywords": ["libpng", "png", "png::png"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libpng"
    },
    "zlib": {
        "headers": ["zlib.h"],
        "keywords": ["zlib", "zlib::zlib"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "zlib",
        "nvd_products": [("zlib", "zlib")],
    },
    "curl": {
        "headers": ["curl/curl.h"],
        "keywords": ["curl", "libcurl", "curl::libcurl"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "curl",
        "nvd_products": [("haxx", "curl"), ("haxx", "libcurl")],
    },
    "sqlite": {
        "headers": ["sqlite3.h"],
        "keywords": ["sqlite", "sqlite3", "sqlite::sqlite3"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "sqlite"
    },
    "libxml2": {
        "headers": ["libxml/parser.h", "libxml/tree.h"],
        "keywords": ["libxml2", "xml2"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libxml2"
    },
    "boost": {
        "headers": ["boost/asio.hpp", "boost/filesystem.hpp", "boost/algorithm/string.hpp"],
        "keywords": ["boost", "boost::filesystem", "boost::system"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "boost"
    },
    "protobuf": {
        "headers": ["google/protobuf/message.h", "google/protobuf/descriptor.h"],
        "keywords": ["protobuf", "libprotobuf", "protobuf::libprotobuf"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "protobuf"
    },
    "grpc": {
        "headers": ["grpc/grpc.h", "grpcpp/grpcpp.h"],
        "keywords": ["grpc", "grpc++", "grpc::grpc++"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "grpc"
    },
    "expat": {
        "headers": ["expat.h"],
        "keywords": ["expat", "expat::expat"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "expat"
    },
    "libjpeg-turbo": {
        "headers": ["jpeglib.h", "turbojpeg.h"],
        "keywords": ["libjpeg", "jpeg", "turbojpeg", "libjpeg-turbo"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libjpeg-turbo"
    },
    "freetype": {
        "headers": ["ft2build.h", "freetype/freetype.h"],
        "keywords": ["freetype", "freetype2"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "freetype"
    },
    "libssh2": {
        "headers": ["libssh2.h"],
        "keywords": ["libssh2", "ssh2"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "libssh2"
    },
    "yaml-cpp": {
        "headers": ["yaml-cpp/yaml.h"],
        "keywords": ["yaml-cpp", "yaml_cpp"],
        "ecosystem_candidates": ["OSS-Fuzz"],
        "purl_name": "yaml-cpp"
    }
}

SYSTEM_HEADER_PREFIXES = {
    "stdio", "stdlib", "string", "strings", "stdint", "stddef", "unistd",
    "errno", "time", "math", "vector", "string", "map", "set", "memory",
    "algorithm", "iostream", "fstream", "sstream", "utility", "limits",
    "ctype", "stdbool", "stdarg", "assert", "stddef", "limits", "float",
    "wchar", "sys", "fcntl", "dirent"
}


def extract_includes(source_files):
    includes = []
    for f in source_files:
        for delimiter, header in INCLUDE_PATTERN.findall(f["content"]):
            includes.append({
                "file": f["relative_path"],
                "header": header,
                "delimiter": delimiter,
                "include_style": "system" if delimiter == "<" else "quoted"
            })
    return includes


def infer_components(source_files, metadata_files):
    global IGNORED_HEADERS
    IGNORED_HEADERS = []
    evidence = defaultdict(list)

    _infer_from_includes(source_files, evidence)
    _infer_from_metadata(metadata_files, evidence)

    components = []
    for name, ev in evidence.items():
        info = KNOWN_COMPONENTS.get(name, {})
        components.append({
            "name": name,
            "version": infer_version_from_evidence(ev),
            "evidence": ev,
            "ecosystem_candidates": info.get("ecosystem_candidates", []),
            "purl_name": info.get("purl_name", name),
            "nvd_products": info.get("nvd_products", []),
        })

    return components


def get_ignored_headers():
    return list(IGNORED_HEADERS)


def _infer_from_includes(source_files, evidence):
    for item in extract_includes(source_files):
        header = item["header"].lower()
        normalized = normalize_header_component(header, item.get("include_style"))
        if normalized:
            evidence[normalized].append({
                "source": "include",
                "file": item["file"],
                "evidence": f'#include <{item["header"]}>',
                "version_hint": None
            })
            continue
        IGNORED_HEADERS.append({
            "file": item["file"],
            "header": item["header"],
            "include_style": item.get("include_style"),
            "component_origin": infer_ignored_header_origin(header, item.get("include_style")),
            "reason": "system_or_internal_header_not_queried_for_cve",
        })


def _infer_from_metadata(metadata_files, evidence):
    for mf in metadata_files:
        name = mf["name"].lower()
        content = mf["content"]

        if name == "cmakelists.txt":
            _parse_cmake(mf, evidence)
        elif name in {"makefile", "makefile"}:
            _parse_makefile(mf, evidence)
        elif name == "vcpkg.json":
            _parse_vcpkg_json(mf, evidence)
        elif name == "conanfile.txt":
            _parse_conanfile(mf, evidence)
        else:
            _parse_generic_metadata(mf, evidence)


def _parse_cmake(mf, evidence):
    text = mf["content"]
    lower = text.lower()

    # find_package(OpenSSL REQUIRED)
    for pkg in re.findall(r'find_package\s*\(\s*([A-Za-z0-9_\-]+)', text, flags=re.IGNORECASE):
        normalized = normalize_component_name(pkg)
        add_dependency_evidence(evidence, normalized or pkg, "CMakeLists.txt", mf["relative_path"], f"find_package({pkg})")

    for lib in re.findall(r'(?:^|\s)-l([A-Za-z0-9_\-+.]+)', text):
        normalized = normalize_component_name(lib)
        add_dependency_evidence(evidence, normalized or lib, "CMakeLists.txt", mf["relative_path"], f"-l{lib}")

    # target_link_libraries(app OpenSSL::SSL zlib ...)
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": "CMakeLists.txt",
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })


def _parse_makefile(mf, evidence):
    lower = mf["content"].lower()
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": mf["name"],
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })
    for lib in re.findall(r'(?:^|\s)-l([A-Za-z0-9_\-+.]+)', mf["content"]):
        normalized = normalize_component_name(lib)
        add_dependency_evidence(evidence, normalized or lib, mf["name"], mf["relative_path"], f"-l{lib}")


def _parse_vcpkg_json(mf, evidence):
    try:
        data = json.loads(mf["content"])
    except Exception:
        return

    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        if isinstance(dep, str):
            dep_name = dep
            version_hint = None
        elif isinstance(dep, dict):
            dep_name = dep.get("name")
            version_hint = dep.get("version>=") or dep.get("version") or dep.get("version-string")
        else:
            continue

        normalized = normalize_component_name(dep_name)
        add_dependency_evidence(evidence, normalized or dep_name, "vcpkg.json", mf["relative_path"], dep_name, version_hint)


def _parse_conanfile(mf, evidence):
    for line in mf["lines"]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Common form: openssl/1.1.1t
        match = re.match(r'([A-Za-z0-9_\-]+)\s*/\s*([A-Za-z0-9_\.\-\+]+)', stripped)
        if not match:
            continue

        dep_name, version = match.group(1), match.group(2)
        normalized = normalize_component_name(dep_name)
        add_dependency_evidence(evidence, normalized or dep_name, "conanfile.txt", mf["relative_path"], stripped, version)


def _parse_generic_metadata(mf, evidence):
    lower = mf["content"].lower()
    for component_name, info in KNOWN_COMPONENTS.items():
        for keyword in info.get("keywords", []):
            if keyword.lower() in lower:
                evidence[component_name].append({
                    "source": mf["name"],
                    "file": mf["relative_path"],
                    "evidence": keyword,
                    "version_hint": None
                })


def normalize_component_name(name):
    if not name:
        return None
    lower = str(name).strip().lower()

    # Direct alias match.
    alias_map = {
        "openssl": "openssl",
        "ssl": "openssl",
        "crypto": "openssl",
        "libssl": "openssl",
        "libcrypto": "openssl",

        "png": "libpng",
        "libpng": "libpng",

        "zlib": "zlib",

        "curl": "curl",
        "libcurl": "curl",

        "sqlite": "sqlite",
        "sqlite3": "sqlite",

        "xml2": "libxml2",
        "libxml2": "libxml2",

        "boost": "boost",
        "boost_system": "boost",
        "boost_filesystem": "boost",
        "protobuf": "protobuf",
        "libprotobuf": "protobuf",
        "grpc": "grpc",
        "grpc++": "grpc",
        "expat": "expat",
        "jpeg": "libjpeg-turbo",
        "libjpeg": "libjpeg-turbo",
        "turbojpeg": "libjpeg-turbo",
        "freetype": "freetype",
        "freetype2": "freetype",
        "ssh2": "libssh2",
        "libssh2": "libssh2",
        "yaml-cpp": "yaml-cpp",
        "yaml_cpp": "yaml-cpp",
    }

    if lower in alias_map:
        return alias_map[lower]

    for component_name, info in KNOWN_COMPONENTS.items():
        if lower in [kw.lower() for kw in info.get("keywords", [])]:
            return component_name

    if is_reasonable_package_name(lower):
        return lower

    return None


def normalize_header_component(header, include_style="system"):
    for component_name, info in KNOWN_COMPONENTS.items():
        if header in [h.lower() for h in info.get("headers", [])]:
            return component_name

    if "/" not in header:
        stem = header.rsplit(".", 1)[0]
        if stem in SYSTEM_HEADER_PREFIXES:
            return None
        if include_style == "quoted":
            return None
        return normalize_component_name(stem) if stem in KNOWN_COMPONENTS else None

    prefix = header.split("/", 1)[0]
    normalized = normalize_component_name(prefix)
    return normalized if normalized in KNOWN_COMPONENTS else None


def infer_ignored_header_origin(header, include_style):
    stem = header.rsplit(".", 1)[0].split("/", 1)[0]
    if include_style == "quoted":
        return "internal_header"
    if stem in SYSTEM_HEADER_PREFIXES:
        return "system_header"
    return "unknown_header"


def add_dependency_evidence(evidence, name, source, file, evidence_text, version_hint=None):
    normalized = normalize_component_name(name)
    if not normalized:
        return
    evidence[normalized].append({
        "source": source,
        "file": file,
        "evidence": str(evidence_text),
        "version_hint": version_hint
    })


def is_reasonable_package_name(name):
    if not name:
        return False
    if name in SYSTEM_HEADER_PREFIXES:
        return False
    return bool(re.fullmatch(r'[a-z0-9][a-z0-9_.+\-]{1,63}', name))


def infer_version_from_evidence(evidence_items):
    for item in evidence_items:
        if item.get("version_hint"):
            return item["version_hint"]
    return "unknown"


def deduplicate_evidence(evidence_items):
    seen = set()
    result = []
    for item in evidence_items:
        key = (item.get("source"), item.get("file"), item.get("evidence"), item.get("version_hint"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
