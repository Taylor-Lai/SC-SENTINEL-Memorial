import re
from core.id_generator import make_id

"""
Agent B - Context Pruning and Code Slicing

Part 1 upgraded version:
1. Extract file-level context:
   - #include
   - #define
   - typedef
   - struct / enum
   - simple global variables
2. Extract function bodies with brace matching.
3. Infer simple call relationships:
   - callee_functions
   - call_chain_upstream
4. Add risk keywords for Agent C / LLM prompt prioritization.
5. Build LLM-friendly code slices.
"""

FUNCTION_SIGNATURE_PATTERN = re.compile(
    r'^\s*(?:static\s+)?(?:inline\s+)?(?:extern\s+)?'
    r'(?:[A-Za-z_][\w\s\*\(\)]*?|\*)\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{'
)

RISK_KEYWORDS = [
    "malloc", "calloc", "realloc", "free",
    "strcpy", "strncpy", "strcat", "sprintf", "snprintf",
    "printf", "fprintf", "vprintf", "vfprintf", "syslog",
    "memcpy", "memmove", "memset",
    "gets", "scanf", "sscanf",
    "new", "delete"
]

RISK_KEYWORD_WEIGHTS = {
    "gets": 5,
    "strcpy": 4,
    "strcat": 4,
    "sprintf": 4,
    "memcpy": 3,
    "memmove": 3,
    "free": 3,
    "realloc": 3,
    "scanf": 3,
    "sscanf": 3,
    "printf": 2,
    "fprintf": 2,
    "vprintf": 2,
    "vfprintf": 2,
    "syslog": 2,
    "malloc": 1,
    "calloc": 1,
    "snprintf": 1,
    "new": 1,
    "delete": 1,
}

PRIORITY_ORDER = {"high": 3, "medium": 2, "low": 1}

CONTROL_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof"
}

HEAP_WRITE_PATTERN = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|-=|=)'
)
SIZE_CALC_PATTERN = re.compile(r'\b(strlen|sizeof|encode_utf8)\s*\(')


def run_agent_b(source_files):
    """
    Main entry for Agent B.

    Input:
        source_files: output of core.file_scanner.scan_source_files()

    Output:
        {
          "agent": "...",
          "slices": [...],
          "summary": {...}
        }
    """
    all_functions = []

    for file_obj in source_files:
        context = extract_file_context(file_obj)
        functions = extract_functions_from_file(file_obj)

        for fn in functions:
            fn["context"] = context
            fn["parameters"] = extract_function_parameters(fn["signature"])
            fn["local_variables"] = extract_local_variables(fn["body"])
            fn["effect_summary"] = infer_effect_summary(fn)
            all_functions.append(fn)

    known_function_names = {fn["function_name"] for fn in all_functions}

    for fn in all_functions:
        fn["callee_functions"] = infer_callees(fn, known_function_names)
        fn["call_chain_upstream"] = infer_callers(fn, all_functions)

    call_graph = build_call_graph(all_functions)
    memory_effects = {
        fn["function_name"]: fn["effect_summary"]
        for fn in all_functions
    }

    slices = []
    for idx, fn in enumerate(all_functions, start=1):
        slice_id = make_id("SLICE", idx)

        risk_keywords = find_risk_keywords(fn)
        cross_function_context = build_cross_function_context(fn, all_functions)
        risk_score = score_slice_risk(fn, risk_keywords, cross_function_context)
        code_slice = build_slice_code(fn, risk_keywords, cross_function_context)

        slices.append({
            "slice_id": slice_id,
            "target_file": fn["file"],
            "target_function": fn["function_name"],
            "line_range": [fn["start_line"], fn["end_line"]],

            "related_includes": fn["context"]["includes"],
            "related_macros": fn["context"]["macros"],
            "related_types": fn["context"]["types"],
            "related_globals": fn["context"]["globals"],

            "call_chain_upstream": fn["call_chain_upstream"],
            "callee_functions": fn["callee_functions"],
            "risk_keywords": risk_keywords,
            "risk_score": risk_score,
            "audit_priority": classify_audit_priority(risk_score),
            "dataflow_hints": infer_dataflow_hints(fn),
            "source_sink_pairs": infer_source_sink_pairs(fn),
            "caller_count": len(fn["call_chain_upstream"]),
            "callee_count": len(fn["callee_functions"]),
            "parameters": fn["parameters"],
            "local_variables": fn["local_variables"],
            "effect_summary": fn["effect_summary"],
            "cross_function_context": cross_function_context,
            "body_line_count": count_non_empty_lines(fn["body"]),
            "context_line_count": count_context_lines(fn["context"]),

            "code": code_slice,
            "notes": (
                "Part 1 slice: function body + file-level context "
                "+ simple call graph + memory-risk keywords."
            )
        })

    slices = sorted(
        slices,
        key=lambda s: (PRIORITY_ORDER.get(s["audit_priority"], 0), s["risk_score"], s["slice_id"]),
        reverse=True
    )

    return {
        "agent": "Agent B - Context Pruning and Code Slicing",
        "slices": slices,
        "program_model": build_program_model(all_functions, call_graph, memory_effects),
        "call_graph": call_graph,
        "memory_effects": memory_effects,
        "summary": {
            "total_slices": len(slices),
            "total_source_files": len(source_files),
            "slices_with_risk_keywords": sum(1 for s in slices if s["risk_keywords"]),
            "high_priority_slices": sum(1 for s in slices if s["audit_priority"] == "high"),
            "medium_priority_slices": sum(1 for s in slices if s["audit_priority"] == "medium"),
            "cross_function_slices": sum(1 for s in slices if s.get("cross_function_context")),
        }
    }


# ----------------------------------------------------------------------
# 1. File-level context extraction
# ----------------------------------------------------------------------

def extract_file_context(file_obj):
    lines = file_obj["lines"]

    includes = extract_includes(lines)
    macros = extract_macros(lines)
    types = extract_type_blocks(lines)
    function_ranges = extract_function_ranges(file_obj)
    globals_ = extract_global_variables(lines, function_ranges)

    return {
        "includes": includes,
        "macros": macros,
        "types": types,
        "globals": globals_
    }


def extract_includes(lines):
    result = []
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#include"):
            result.append({
                "line": idx,
                "code": stripped
            })
    return result


def extract_macros(lines):
    result = []
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped.startswith("#define"):
            idx += 1
            continue

        start = idx
        block = [line.rstrip()]

        # Support multi-line macros ending with backslash.
        while block[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
            idx += 1
            block.append(lines[idx].rstrip())

        result.append({
            "line_range": [start + 1, idx + 1],
            "code": "\n".join(block).strip()
        })

        idx += 1

    return result


def extract_type_blocks(lines):
    """
    Extract simple typedef / struct / enum blocks.

    This is not a full C parser. It is a practical approximation for Part 1.
    """
    result = []
    idx = 0

    while idx < len(lines):
        stripped = lines[idx].strip()

        is_type_start = (
            stripped.startswith("typedef ")
            or re.match(r'^(struct|enum)\s+[A-Za-z_][A-Za-z0-9_]*\s*\{?', stripped)
        )

        if not is_type_start:
            idx += 1
            continue

        start = idx
        block = [lines[idx].rstrip()]
        brace_balance = lines[idx].count("{") - lines[idx].count("}")

        # Continue until semicolon if it is a type declaration.
        while idx + 1 < len(lines):
            if ";" in lines[idx] and brace_balance <= 0:
                break

            idx += 1
            block.append(lines[idx].rstrip())
            brace_balance += lines[idx].count("{") - lines[idx].count("}")

            if ";" in lines[idx] and brace_balance <= 0:
                break

        result.append({
            "line_range": [start + 1, idx + 1],
            "code": "\n".join(block).strip()
        })

        idx += 1

    return result


def extract_global_variables(lines, function_ranges):
    """
    Extract simple global variable declarations outside function bodies.

    Heuristic:
    - only single-line declarations ending with ;
    - skip preprocessor lines, typedef, struct, enum
    - skip function prototypes / function calls containing '('
    """
    globals_ = []

    for idx, line in enumerate(lines, start=1):
        if is_line_inside_ranges(idx, function_ranges):
            continue

        stripped = line.strip()

        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith(("typedef", "struct", "enum")):
            continue
        if not stripped.endswith(";"):
            continue
        if "(" in stripped or ")" in stripped:
            continue

        looks_like_decl = re.match(
            r'^(static\s+|extern\s+|const\s+|unsigned\s+|signed\s+|long\s+|short\s+|int\s+|char\s+|float\s+|double\s+|size_t\s+|bool\s+|uint\d+_t\s+|int\d+_t\s+)+',
            stripped
        )

        if looks_like_decl:
            globals_.append({
                "line": idx,
                "code": stripped
            })

    return globals_


# ----------------------------------------------------------------------
# 2. Function extraction
# ----------------------------------------------------------------------

def extract_functions_from_file(file_obj):
    lines = file_obj["lines"]
    functions = []
    idx = 0

    while idx < len(lines):
        maybe_signature, start_idx, open_brace_idx = collect_function_signature(lines, idx)

        if maybe_signature is None:
            idx += 1
            continue

        match = FUNCTION_SIGNATURE_PATTERN.match(maybe_signature)
        if not match:
            idx += 1
            continue

        function_name = match.group(1)

        if function_name in CONTROL_KEYWORDS:
            idx += 1
            continue

        end_idx = find_matching_brace(lines, open_brace_idx)
        if end_idx is None:
            idx += 1
            continue

        body_lines = lines[start_idx:end_idx + 1]

        functions.append({
            "file": file_obj["relative_path"],
            "function_name": function_name,
            "signature": maybe_signature,
            "start_line": start_idx + 1,
            "end_line": end_idx + 1,
            "body": "\n".join(body_lines)
        })

        idx = end_idx + 1

    return functions


def extract_function_ranges(file_obj):
    return [
        [fn["start_line"], fn["end_line"]]
        for fn in extract_functions_from_file(file_obj)
    ]


def collect_function_signature(lines, start_idx, max_signature_lines=6):
    """
    Support both one-line and simple multi-line signatures.

    Example:
        int foo(
            int a,
            char *b
        ) {
            ...
        }
    """
    parts = []
    idx = start_idx

    while idx < len(lines) and idx < start_idx + max_signature_lines:
        line = lines[idx]
        parts.append(line.strip())

        if "{" in line:
            signature = " ".join(parts)
            return signature, start_idx, idx

        # A declaration ending with ; is not a function definition.
        if ";" in line:
            return None, None, None

        idx += 1

    return None, None, None


def find_matching_brace(lines, open_brace_idx):
    brace_balance = 0
    seen_open = False

    for idx in range(open_brace_idx, len(lines)):
        line = strip_string_literals(lines[idx])

        brace_balance += line.count("{")
        brace_balance -= line.count("}")

        if "{" in line:
            seen_open = True

        if seen_open and brace_balance == 0:
            return idx

    return None


def strip_string_literals(line):
    """
    Remove string contents to reduce brace matching errors caused by "{...}" inside strings.
    """
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line)


def is_line_inside_ranges(line_no, ranges):
    for start, end in ranges:
        if start <= line_no <= end:
            return True
    return False


# ----------------------------------------------------------------------
# 3. Call graph and risk keyword extraction
# ----------------------------------------------------------------------

def infer_callees(function_obj, known_function_names):
    """
    Infer functions called by the current function.

    Important:
    We only search inside the function body, not the function signature.
    Otherwise, `int main()` will be wrongly treated as a call to main().
    """
    inner_body = get_function_inner_body(function_obj["body"])
    body = remove_comments(inner_body)

    candidates = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', body))

    callees = sorted(
        name for name in candidates
        if name in known_function_names
        and name != function_obj["function_name"]
    )

    return callees


def infer_callers(target_fn, all_functions):
    """
    Infer upstream callers of the target function.

    Important:
    We search only inside each candidate function's inner body.
    This avoids false positives caused by function signatures like `int main()`.
    """
    callers = []
    target_name = target_fn["function_name"]

    for fn in all_functions:
        if fn is target_fn:
            continue

        inner_body = get_function_inner_body(fn["body"])
        body = remove_comments(inner_body)

        if re.search(rf'\b{re.escape(target_name)}\s*\(', body):
            callers.append({
                "function": fn["function_name"],
                "file": fn["file"],
                "line_range": [fn["start_line"], fn["end_line"]]
            })

    return callers


def find_risk_keywords(function_obj):
    body = remove_comments(function_obj["body"])
    found = []

    for keyword in RISK_KEYWORDS:
        if re.search(rf'\b{re.escape(keyword)}\b', body):
            found.append(keyword)

    return found


def score_slice_risk(function_obj, risk_keywords, cross_function_context=None):
    score = sum(RISK_KEYWORD_WEIGHTS.get(keyword, 1) for keyword in risk_keywords)
    if function_obj.get("call_chain_upstream"):
        score += 1
    if function_obj.get("callee_functions"):
        score += min(len(function_obj["callee_functions"]), 3)
    effects = function_obj.get("effect_summary", {})
    if any(effects.get(key) for key in ("frees_param", "frees_field", "writes_param", "stores_alias", "uses_after_call")):
        score += 2
    if effects.get("allocates") and effects.get("buffer_writes"):
        score += 4
    if effects.get("suspicious_size_calculations"):
        score += min(len(effects["suspicious_size_calculations"]), 3)
    if "unsafe_copy_sink" in infer_dataflow_hints(function_obj):
        score += 2
    if cross_function_context:
        score += min(len(cross_function_context), 4)
    return score


def classify_audit_priority(score):
    if score >= 6:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def count_non_empty_lines(code):
    return sum(1 for line in code.splitlines() if line.strip())


def count_context_lines(context):
    total = 0
    for key in ("includes", "macros", "types", "globals"):
        for item in context.get(key, []):
            if "line_range" in item and isinstance(item["line_range"], list):
                start, end = item["line_range"]
                total += max(1, end - start + 1)
            else:
                total += 1
    return total


def infer_dataflow_hints(function_obj):
    body = remove_comments(function_obj["body"])
    hints = []
    if re.search(r'\b(argv|argc|stdin|fread|read|recv|scanf|sscanf|gets)\b', body):
        hints.append("external_input")
    if re.search(r'\b(malloc|calloc|realloc|new)\b', body):
        hints.append("heap_allocation")
    if re.search(r'\bfree\s*\(', body):
        hints.append("explicit_free")
    if re.search(r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets)\s*\(', body):
        hints.append("unsafe_copy_sink")
    if re.search(r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(', body):
        hints.append("format_sink")
    if re.search(r'\[[^\]]+\]', body) or re.search(r'->|\*\s*[A-Za-z_]', body):
        hints.append("pointer_or_index_access")
    return sorted(set(hints))


def infer_source_sink_pairs(function_obj):
    body = remove_comments(function_obj["body"])
    sources = []
    sinks = []

    source_patterns = {
        "argv": r'\bargv\b',
        "stdin": r'\bstdin\b',
        "file_read": r'\b(fread|read)\s*\(',
        "network_recv": r'\brecv\s*\(',
        "scanf_input": r'\b(scanf|sscanf|gets)\s*\(',
    }
    sink_patterns = {
        "free": r'\bfree\s*\(',
        "copy": r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets)\s*\(',
        "format": r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(',
        "pointer_access": r'(->|\*\s*[A-Za-z_]|\[[^\]]+\])',
    }

    for name, pattern in source_patterns.items():
        if re.search(pattern, body):
            sources.append(name)
    for name, pattern in sink_patterns.items():
        if re.search(pattern, body):
            sinks.append(name)

    if not sources and ("const_char_ptr" in body or "char *" in body or "char*" in body):
        sources.append("function_parameter")

    return [
        {"source": source, "sink": sink}
        for source in sorted(set(sources))
        for sink in sorted(set(sinks))
    ]


def remove_comments(code):
    """
    Remove // and /* */ comments for rough pattern matching.
    """
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*', '', code)
    return code

def get_function_inner_body(function_body):
    """
    Return function content inside the outermost braces.
    This avoids treating the function signature itself as a function call.
    Example:
        int main() {
            foo();
        }
    We only want:
        foo();
    """
    start = function_body.find("{")
    end = function_body.rfind("}")

    if start == -1 or end == -1 or end <= start:
        return function_body

    return function_body[start + 1:end]


# ----------------------------------------------------------------------
# 4. Lightweight semantic program model
# ----------------------------------------------------------------------

def extract_function_parameters(signature):
    open_idx = signature.find("(")
    close_idx = signature.rfind(")")
    if open_idx < 0 or close_idx <= open_idx:
        return []
    params_text = signature[open_idx + 1:close_idx].strip()
    if not params_text or params_text == "void":
        return []
    params = []
    for raw in split_top_level_commas(params_text):
        text = raw.strip()
        if not text:
            continue
        name_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$', text)
        param_name = name_match.group(1) if name_match else text
        params.append({
            "name": param_name,
            "declaration": text,
            "is_pointer": "*" in text or "[" in text or text.endswith("]"),
            "is_size": bool(re.search(r'\b(size_t|int|uint\d+_t|long|short)\b', text)) and re.search(r'(len|size|count|idx|index|n)\b', text, re.I) is not None,
        })
    return params


def split_top_level_commas(text):
    parts = []
    current = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current or text.strip():
        parts.append("".join(current))
    return parts


def extract_local_variables(body):
    cleaned = remove_comments(body)
    locals_ = []
    decl_pattern = re.compile(
        r'\b(?:struct\s+[A-Za-z_][\w]*\s+)?(?:char|int|size_t|unsigned\s+char|uint\d+_t|int\d+_t|long|short|float|double|void)\s+([*\s]*)([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]+\])?',
    )
    for idx, line in enumerate(cleaned.splitlines(), start=1):
        stripped = line.strip()
        if "(" in stripped and not stripped.startswith(("char ", "int ", "size_t ", "unsigned ", "uint", "struct ")):
            continue
        for match in decl_pattern.finditer(stripped):
            locals_.append({
                "name": match.group(2),
                "line_offset": idx,
                "is_pointer": "*" in match.group(1),
                "is_array": bool(match.group(3)),
                "declaration": stripped,
            })
    return locals_


def infer_effect_summary(function_obj):
    body = remove_comments(get_function_inner_body(function_obj["body"]))
    params = {p["name"] for p in function_obj.get("parameters", [])}
    frees = re.findall(r'\bfree\s*\(\s*([^)]+?)\s*\)', body)
    aliases = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\]|->[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_]*)?)\s*;', body)
    writes = re.findall(r'\b(?:strcpy|strcat|sprintf|snprintf|memcpy|memmove|gets)\s*\(\s*([^,\)]+)', body)
    allocations = extract_allocations(body)
    buffer_writes = []
    for line in body.splitlines():
        m = HEAP_WRITE_PATTERN.search(line)
        if not m:
            continue
        target = m.group(1)
        if target in allocations:
            buffer_writes.append(line.strip())
    suspicious_size_calculations = [
        line.strip()
        for line in body.splitlines()
        if SIZE_CALC_PATTERN.search(line)
    ]
    return_expr = None
    m = re.search(r'\breturn\s+([^;]+);', body)
    if m:
        return_expr = m.group(1).strip()

    return {
        "allocates": allocations,
        "frees": [expr.strip() for expr in frees],
        "frees_param": [expr.strip() for expr in frees if base_identifier(expr) in params],
        "frees_field": [expr.strip() for expr in frees if "->" in expr or "." in expr or "[" in expr],
        "writes": [expr.strip() for expr in writes],
        "writes_param": [expr.strip() for expr in writes if base_identifier(expr) in params],
        "returns_allocated": bool(return_expr and any(name in return_expr for name in extract_allocations(body))),
        "return_expr": return_expr,
        "stores_alias": [{"target": left, "source": right} for left, right in aliases],
        "uses_after_call": [],
        "format_sinks": re.findall(r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(', body),
        "buffer_writes": buffer_writes,
        "suspicious_size_calculations": suspicious_size_calculations,
    }


def extract_allocations(body):
    names = []
    for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(', body):
        names.append(match.group(1))
    return names


def base_identifier(expr):
    expr = str(expr).strip()
    expr = expr.lstrip("&*").strip()
    match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', expr)
    return match.group(1) if match else expr


def build_call_graph(all_functions):
    nodes = []
    edges = []
    for fn in all_functions:
        nodes.append({
            "function": fn["function_name"],
            "file": fn["file"],
            "line_range": [fn["start_line"], fn["end_line"]],
        })
        for callee in fn.get("callee_functions", []):
            edges.append({
                "caller": fn["function_name"],
                "callee": callee,
                "caller_file": fn["file"],
            })
    return {"nodes": nodes, "edges": edges}


def build_program_model(all_functions, call_graph, memory_effects):
    return {
        "functions": [
            {
                "file": fn["file"],
                "function": fn["function_name"],
                "line_range": [fn["start_line"], fn["end_line"]],
                "parameters": fn.get("parameters", []),
                "local_variables": fn.get("local_variables", []),
                "callee_functions": fn.get("callee_functions", []),
                "caller_functions": fn.get("call_chain_upstream", []),
                "effect_summary": fn.get("effect_summary", {}),
            }
            for fn in all_functions
        ],
        "call_graph": call_graph,
        "memory_effects": memory_effects,
    }


def build_cross_function_context(function_obj, all_functions):
    by_name = {fn["function_name"]: fn for fn in all_functions}
    context = []
    for callee_name in function_obj.get("callee_functions", []):
        callee = by_name.get(callee_name)
        if not callee:
            continue
        effects = callee.get("effect_summary", {})
        interesting = []
        if effects.get("frees_param") or effects.get("frees_field"):
            interesting.append("callee_frees_argument")
        if effects.get("writes_param") or effects.get("writes"):
            interesting.append("callee_writes_argument")
        if effects.get("returns_allocated"):
            interesting.append("callee_returns_allocated")
        if interesting:
            context.append({
                "caller": function_obj["function_name"],
                "callee": callee_name,
                "callee_file": callee["file"],
                "callee_effects": effects,
                "risk_signals": sorted(set(interesting)),
                "trace": f"{function_obj['function_name']} -> {callee_name}: {', '.join(sorted(set(interesting)))}",
            })
    for caller in function_obj.get("call_chain_upstream", []):
        context.append({
            "caller": caller.get("function"),
            "callee": function_obj["function_name"],
            "caller_file": caller.get("file"),
            "risk_signals": ["upstream_call"],
            "trace": f"{caller.get('function')} -> {function_obj['function_name']}",
        })
    return context


# ----------------------------------------------------------------------
# 5. LLM-friendly slice construction
# ----------------------------------------------------------------------

def build_slice_code(function_obj, risk_keywords, cross_function_context=None):
    context = function_obj["context"]
    parts = []

    parts.append("/* ===== SENTINEL Agent B Slice ===== */")
    parts.append(f"/* File: {function_obj['file']} */")
    parts.append(f"/* Target Function: {function_obj['function_name']} */")
    parts.append(f"/* Line Range: {function_obj['start_line']}-{function_obj['end_line']} */")

    if risk_keywords:
        parts.append(f"/* Risk Keywords: {', '.join(risk_keywords)} */")
    else:
        parts.append("/* Risk Keywords: none */")

    if function_obj.get("call_chain_upstream"):
        callers = ", ".join(
            item["function"] for item in function_obj["call_chain_upstream"]
        )
        parts.append(f"/* Upstream Callers: {callers} */")
    else:
        parts.append("/* Upstream Callers: none */")

    if function_obj.get("callee_functions"):
        parts.append(f"/* Callees: {', '.join(function_obj['callee_functions'])} */")
    else:
        parts.append("/* Callees: none */")

    effects = function_obj.get("effect_summary") or {}
    parts.append(f"/* Memory Effects: {effects} */")
    if cross_function_context:
        parts.append("/* Cross Function Context: */")
        for item in cross_function_context:
            parts.append(f"/* - {item.get('trace')} */")

    parts.append("\n/* ===== Related Includes ===== */")
    if context["includes"]:
        parts.extend(item["code"] for item in context["includes"])
    else:
        parts.append("/* none */")

    parts.append("\n/* ===== Related Macros ===== */")
    if context["macros"]:
        parts.extend(item["code"] for item in context["macros"])
    else:
        parts.append("/* none */")

    parts.append("\n/* ===== Related Types typedef / struct / enum ===== */")
    if context["types"]:
        parts.extend(item["code"] for item in context["types"])
    else:
        parts.append("/* none */")

    parts.append("\n/* ===== Related Global Variables ===== */")
    if context["globals"]:
        parts.extend(item["code"] for item in context["globals"])
    else:
        parts.append("/* none */")

    parts.append("\n/* ===== Target Function Body ===== */")
    parts.append(function_obj["body"])

    return "\n".join(parts)
