#!/usr/bin/env python3
"""
parse.py — Parse EndpointSecurity API headers into endpointsecurity-data.js and endpointsecurity.json

Usage:
    python3 parse.py
"""

import re
import json
import argparse
import subprocess
from pathlib import Path

# ─── Config ───────────────────────────────────────────────────────────────────

_p = argparse.ArgumentParser(description="Parse EndpointSecurity headers")
_p.add_argument(
    "--sdk-path",
    default=None,
    metavar="PATH",
    help="Explicit SDK root (e.g. /path/to/MacOSX.sdk); skips xcrun",
)
_args = _p.parse_args()

if _args.sdk_path:
    SDK = _args.sdk_path
else:
    SDK = subprocess.check_output(["xcrun", "--show-sdk-path"]).decode().strip()
ES_DIR = Path(SDK) / "usr/include/EndpointSecurity"
OUT_DIR = Path(__file__).parent / "generated"
OUT_DIR.mkdir(exist_ok=True)

HEADERS = ["ESTypes.h", "ESMessage.h", "ESClient.h"]


def read_header(name: str, seen: set = None) -> str:
    """Read a header and inline any EndpointSecurity-local #include directives."""
    if seen is None:
        seen = set()
    if name in seen:
        return ""
    seen.add(name)
    content = (ES_DIR / name).read_text()

    def inline(m):
        included = m.group(1)
        if (ES_DIR / included).exists():
            return read_header(included, seen)
        return m.group(0)

    return re.sub(r"#include\s*<EndpointSecurity/([^>]+)>", inline, content)


# ─── Comment parsing ──────────────────────────────────────────────────────────


def clean_block_comment(text: str) -> str:
    lines = []
    for line in text.split("\n"):
        line = re.sub(r"^\s*/\*+\s?", "", line)
        line = re.sub(r"\s*\*+/\s*$", "", line)
        line = re.sub(r"^\s*\*\s?", "", line)
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def parse_doc_comment(raw: str) -> dict:
    text = clean_block_comment(raw)
    brief = ""
    fields = {}
    notes = []

    m = re.search(r"@brief\s+(.*?)(?=\n\s*@|\Z)", text, re.DOTALL)
    if m:
        brief = " ".join(m.group(1).split())
    else:
        for line in text.split("\n"):
            s = line.strip()
            if s and not s.startswith("@") and not s.startswith("*"):
                brief = s
                break

    for m in re.finditer(
        r"@field\s+(\w+)\s+(.*?)(?=\n\s*@(?:field|note|discussion|see|warning|deprecated)|\Z)",
        text,
        re.DOTALL,
    ):
        fields[m.group(1)] = " ".join(m.group(2).split())

    for m in re.finditer(
        r"@note\s+(.*?)(?=\n\s*@(?:field|note|discussion|see|warning|deprecated)|\Z)",
        text,
        re.DOTALL,
    ):
        notes.append(" ".join(m.group(1).split()))

    return {"brief": brief, "fields": fields, "notes": notes}


# ─── Brace finder ─────────────────────────────────────────────────────────────


def find_matching_brace(content: str, start: int) -> int:
    """Return position of the } matching the { at start, skipping comments."""
    depth = 0
    i = start
    n = len(content)
    in_line = False
    in_block = False

    while i < n:
        c = content[i]
        if in_line:
            if c == "\n":
                in_line = False
        elif in_block:
            if c == "*" and i + 1 < n and content[i + 1] == "/":
                in_block = False
                i += 1
        elif c == "/" and i + 1 < n:
            if content[i + 1] == "/":
                in_line = True
                i += 1
            elif content[i + 1] == "*":
                in_block = True
                i += 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# ─── Typedef block extractor ──────────────────────────────────────────────────


def extract_typedefs(content: str) -> list:
    """Return list of {kind, name, body, doc} for every typedef struct/union/enum."""
    results = []

    for m in re.finditer(r"typedef\s+(struct|union|enum)\s*(?:\w+\s*)?\{", content):
        kind = m.group(1)
        brace_start = content.rindex("{", m.start(), m.end())
        brace_end = find_matching_brace(content, brace_start)
        if brace_end == -1:
            continue

        body = content[brace_start + 1 : brace_end]

        after = content[brace_end + 1 : brace_end + 80]
        name_m = re.match(r"\s*(\w+)\s*;", after)
        if not name_m:
            continue
        name = name_m.group(1)

        # Find preceding /** ... */ doc comment (nothing but whitespace between)
        before = content[: m.start()]
        doc_comment = ""
        source_start = m.start()
        for cm in re.finditer(r"/\*\*.*?\*/", before, re.DOTALL):
            between = before[cm.end() :].strip()
            if re.fullmatch(r"\s*", between):
                doc_comment = cm.group(0)
                source_start = cm.start()
        # If not found with **, try single * (some structs use /* */)
        if not doc_comment:
            for cm in re.finditer(r"/\*.*?\*/", before, re.DOTALL):
                between = before[cm.end() :].strip()
                if re.fullmatch(r"\s*", between):
                    doc_comment = cm.group(0)
                    source_start = cm.start()

        source = content[source_start : brace_end + 1 + name_m.end()].rstrip()
        doc = (
            parse_doc_comment(doc_comment)
            if doc_comment
            else {"brief": "", "fields": {}, "notes": []}
        )
        results.append(
            {"kind": kind, "name": name, "body": body, "doc": doc, "source": source}
        )

    return results


# ─── Struct body parser ───────────────────────────────────────────────────────


def extract_type_ref(raw_type: str):
    base = re.sub(r"\s*\*.*", "", raw_type).strip()
    base = re.sub(r"\b(const|struct|union)\b\s*", "", base).strip()
    parts = base.split()
    if parts:
        c = parts[-1]
        if re.match(r"^\w+_t$", c):
            return c
    return None


def parse_struct_body(body: str, field_docs: dict) -> list:
    fields = []
    depth = 0

    for line in body.split("\n"):
        opens = line.count("{")
        closes = line.count("}")

        if opens > 0 or closes > 0:
            depth += opens - closes
            continue  # structural line

        stripped = line.strip()
        if not stripped or ";" not in stripped:
            continue

        if re.search(r"\b(reserved|opaque)\b", stripped):
            continue

        since_version = None
        vm = re.search(
            r"/\*\s*field available only if message version >= (\d+)\s*\*/", line
        )
        if vm:
            since_version = int(vm.group(1))

        clean = re.sub(r"/\*.*?\*/", "", line)
        clean = re.sub(r"//.*$", "", clean).strip().rstrip(";").strip()
        if not clean:
            continue

        # Use a search from the right so `const char *data` (no space before name) works
        m = re.search(r"\b(\w+)\s*(?:\[.*?\])?\s*$", clean)
        if not m:
            continue

        name = m.group(1)
        raw_type = clean[: m.start()].strip()

        if name in ("struct", "union", "typedef", "enum", "const", "void"):
            continue
        if raw_type in ("", "typedef", "union", "struct"):
            continue

        display_type = re.sub(r"\*_Nonnull\b", "*", raw_type)
        display_type = re.sub(r"\*_Nullable\b", "*", display_type)
        display_type = " ".join(display_type.split())

        type_ref = extract_type_ref(raw_type)
        doc = field_docs.get(name, "")

        entry: dict = {"name": name, "type": display_type, "doc": doc}
        if type_ref:
            entry["typeRef"] = type_ref
        if since_version is not None:
            entry["sinceVersion"] = since_version
        if depth > 0:
            entry["inUnion"] = True

        fields.append(entry)

    return fields


# ─── Enum body parser ─────────────────────────────────────────────────────────


def parse_enum_body(body: str) -> list:
    values = []
    current_value = 0
    pending_doc: list[str] = []

    for line in body.split("\n"):
        stripped = line.strip()

        m = re.match(r"^///\s*(.*)", stripped)
        if m:
            pending_doc.append(m.group(1))
            continue

        if not stripped or stripped.startswith("/*") or stripped.startswith("*"):
            pending_doc = []
            continue

        inline_doc = ""
        m = re.search(r"//\s*(.*)", stripped)
        if m:
            inline_doc = m.group(1).strip()

        clean = re.sub(r"//.*$", "", stripped).strip().rstrip(",").strip()
        if not clean:
            continue

        m = re.match(r"^(\w+)\s*(?:=\s*(.+))?\s*$", clean)
        if not m:
            pending_doc = []
            continue

        name = m.group(1)
        if name.endswith("_LAST") or name.endswith("_COUNT"):
            pending_doc = []
            continue

        if m.group(2):
            val_str = m.group(2).strip().rstrip(",").strip()
            try:
                current_value = int(val_str, 0)
            except ValueError:
                pass

        doc = " ".join(pending_doc) or inline_doc
        pending_doc = []

        values.append({"name": name, "value": current_value, "doc": doc})
        current_value += 1

    return values


# ─── Event type enum parser ───────────────────────────────────────────────────


def parse_event_types(content: str) -> list:
    for m in re.finditer(r"typedef\s+enum\s*\{", content):
        brace_start = m.end() - 1
        brace_end = find_matching_brace(content, brace_start)
        if brace_end == -1:
            continue
        after = content[brace_end + 1 : brace_end + 60]
        nm = re.match(r"\s*(\w+)\s*;", after)
        if nm and nm.group(1) == "es_event_type_t":
            body = content[brace_start + 1 : brace_end]
            return _parse_event_type_body(body)
    return []


def _parse_event_type_body(body: str) -> list:
    events = []
    current_macos = "10.15"
    current_value = 0

    for line in body.split("\n"):
        stripped = line.strip()

        vm = re.search(r"available beginning in macOS\s+([\d.]+)", stripped)
        if vm:
            current_macos = vm.group(1)

        clean = re.sub(r"//.*$", "", stripped).strip().rstrip(",").strip()
        if not clean or not clean.startswith("ES_EVENT_TYPE_"):
            continue

        m = re.match(r"(ES_EVENT_TYPE_\w+)\s*(?:=\s*(\d+))?", clean)
        if not m:
            continue

        name = m.group(1)
        if name == "ES_EVENT_TYPE_LAST":
            break

        if m.group(2):
            current_value = int(m.group(2))

        if name.startswith("ES_EVENT_TYPE_AUTH_"):
            action = "AUTH"
            category = name[len("ES_EVENT_TYPE_AUTH_") :].lower()
        elif name.startswith("ES_EVENT_TYPE_NOTIFY_"):
            action = "NOTIFY"
            category = name[len("ES_EVENT_TYPE_NOTIFY_") :].lower()
        elif name.startswith("ES_EVENT_TYPE_RESERVED_"):
            action = "RESERVED"
            category = name[len("ES_EVENT_TYPE_") :].lower()
        else:
            current_value += 1
            continue

        events.append(
            {
                "name": name,
                "value": current_value,
                "action": action,
                "category": category,
                "macosVersion": current_macos,
                "struct": None,
            }
        )
        current_value += 1

    return events


# ─── es_events_t union parser ─────────────────────────────────────────────────


def parse_events_union(content: str) -> dict:
    for m in re.finditer(r"typedef\s+union\s*\{", content):
        brace_start = m.end() - 1
        brace_end = find_matching_brace(content, brace_start)
        if brace_end == -1:
            continue
        after = content[brace_end + 1 : brace_end + 60]
        nm = re.match(r"\s*(\w+)\s*;", after)
        if nm and nm.group(1) == "es_events_t":
            body = content[brace_start + 1 : brace_end]
            return _parse_events_union_body(body)
    return {}


def _parse_events_union_body(body: str) -> dict:
    mapping = {}
    for line in body.split("\n"):
        clean = re.sub(r"/\*.*?\*/", "", line)
        clean = re.sub(r"//.*$", "", clean).strip()
        if not clean or not clean.endswith(";"):
            continue
        m = re.match(
            r"(es_event_\w+_t)\s+\*?(?:_Nonnull\s+|_Nullable\s+)?(\w+)\s*;", clean
        )
        if m:
            mapping[m.group(2)] = m.group(1)
    return mapping


# ─── Main ─────────────────────────────────────────────────────────────────────


def main():
    contents = {h: read_header(h) for h in HEADERS}

    # Events
    events = parse_event_types(contents["ESTypes.h"])
    event_to_struct = parse_events_union(contents["ESMessage.h"])
    for e in events:
        e["struct"] = event_to_struct.get(e["category"])

    # Structs and enums
    structs: dict = {}
    enums: dict = {}

    for header, content in contents.items():
        for block in extract_typedefs(content):
            name = block["name"]
            kind = block["kind"]
            doc = block["doc"]

            if kind == "enum":
                if name == "es_event_type_t":
                    continue
                enums[name] = {
                    "brief": doc["brief"],
                    "values": parse_enum_body(block["body"]),
                    "notes": doc["notes"],
                    "source": block["source"],
                }
            else:
                if name == "es_events_t":
                    continue
                structs[name] = {
                    "brief": doc["brief"],
                    "fields": parse_struct_body(block["body"], doc["fields"]),
                    "notes": doc["notes"],
                    "source": block["source"],
                }

    data = {"events": events, "structs": structs, "enums": enums}

    json_path = OUT_DIR / "endpointsecurity.json"
    json_path.write_text(json.dumps(data, indent=2))

    js_path = OUT_DIR / "endpointsecurity-data.js"
    js_path.write_text(
        f"window.ENDPOINT_SECURITY_DATA={json.dumps(data, separators=(',', ':'))};"
    )

    auth_count = sum(1 for e in events if e["action"] == "AUTH")
    notify_count = sum(1 for e in events if e["action"] == "NOTIFY")
    print(f"Events : {len(events)} ({auth_count} AUTH, {notify_count} NOTIFY)")
    print(f"Structs: {len(structs)}")
    print(f"Enums  : {len(enums)}")
    print(f"Written: {json_path}")
    print(f"Written: {js_path}")


if __name__ == "__main__":
    main()
