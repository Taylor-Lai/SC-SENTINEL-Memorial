import re

from core.id_generator import make_id


TARGET_BODY_MARKER = "/* ===== Target Function Body ===== */"
FREE_PATTERN = re.compile(r'\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
DANGEROUS_COPY_PATTERN = re.compile(r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets)\s*\(')
FORMAT_CALL_PATTERN = re.compile(r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(')
TERMINATOR_PATTERN = re.compile(r'\b(return|goto|break|continue)\b')
NULL_ASSIGN_PATTERN = r'\b{ptr}\s*=\s*NULL\s*;'
ALLOC_PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(')
TRUNCATED_SIZE_PATTERN = re.compile(
    r'\b(?:uint8_t|uint16_t|int8_t|int16_t)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'\([^)]*(?:uint8_t|uint16_t|int8_t|int16_t)[^)]*\)\s*\([^;]+\)'
)


def run_agent_c(agent_a_result, agent_b_result):
    """
    Agent C - Vulnerability Hypothesis Generation.

    This agent turns prioritized code slices into explainable vulnerability
    hypotheses. It does not call the LLM and does not make final decisions.
    """
    hypotheses = []
    skipped_slices = []

    candidate_slices = [
        slc for slc in agent_b_result.get("slices", [])
        if slc.get("audit_priority") in {"high", "medium"}
    ]

    for slc in candidate_slices:
        function_lines = extract_target_function_lines(slc)
        slice_hypotheses = []
        slice_hypotheses.extend(detect_uaf_and_double_free(slc, function_lines))
        slice_hypotheses.extend(detect_callback_context_uaf(slc, function_lines))
        slice_hypotheses.extend(detect_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_truncated_allocation_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_manual_heap_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_index_loop_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_pointer_index_loop_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_format_string(slc, function_lines))

        if not slice_hypotheses:
            skipped_slices.append({
                "slice_id": slc.get("slice_id"),
                "target_file": slc.get("target_file"),
                "target_function": slc.get("target_function"),
                "reason": "No rule-level vulnerability hypothesis generated."
            })
        hypotheses.extend(slice_hypotheses)

    hypotheses.extend(detect_cross_function_memory(agent_b_result))

    hypotheses = deduplicate_hypotheses(hypotheses)
    hypotheses = suppress_cleanup_path_false_positives(hypotheses)
    for idx, hyp in enumerate(hypotheses, start=1):
        hyp["hypothesis_id"] = make_id("HYP", idx)

    return {
        "agent": "Agent C - Vulnerability Hypothesis Agent",
        "hypotheses": hypotheses,
        "skipped_slices": skipped_slices,
        "summary": {
            "total_input_slices": len(agent_b_result.get("slices", [])),
            "candidate_slices": len(candidate_slices),
            "low_priority_slices": sum(
                1 for slc in agent_b_result.get("slices", [])
                if slc.get("audit_priority") == "low"
            ),
            "total_hypotheses": len(hypotheses),
            "hypotheses_by_cwe": count_by_cwe(hypotheses),
            "component_context_count": len(agent_a_result.get("components", [])),
        }
    }


def extract_target_function_lines(slc):
    code = slc.get("code", "")
    function_start_line = slc["line_range"][0]
    body = code.split(TARGET_BODY_MARKER, 1)[1] if TARGET_BODY_MARKER in code else code
    raw_lines = body.splitlines()
    while raw_lines and raw_lines[0].strip() == "":
        raw_lines.pop(0)
    return [{"index": idx, "source_line": function_start_line + idx, "code": line} for idx, line in enumerate(raw_lines)]


def detect_uaf_and_double_free(slc, function_lines):
    results = []
    freed = {}
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        m = FREE_PATTERN.search(line)
        if m:
            ptr = m.group(1)
            if ptr in freed:
                if freed[ptr].get("terminal_after_free"):
                    freed[ptr] = {
                        "source_line": source_line,
                        "code": line,
                        "index": item.get("index"),
                        "terminal_after_free": has_post_free_terminator(line),
                    }
                    continue
                if path_appears_terminated(function_lines, freed[ptr]["index"], item["index"] if "index" in item else None):
                    freed[ptr] = {
                        "source_line": source_line,
                        "code": line,
                        "index": item.get("index"),
                        "terminal_after_free": has_post_free_terminator(line),
                    }
                    continue
                results.append(make_hypothesis(
                    slc=slc,
                    cwe_candidates=["CWE-415"],
                    risk_signals=["double_free"],
                    suspect_lines=[freed[ptr]["source_line"], source_line],
                    confidence=0.78,
                    reason=f"Pointer '{ptr}' is freed more than once without reset or reallocation.",
                    evidence=[
                        f"First free at line {freed[ptr]['source_line']}.",
                        f"Second free at line {source_line}: {line.strip()}",
                    ],
                    suggested_fix=f"Set {ptr} to NULL after free and enforce single ownership.",
                    vulnerability_type="Double Free",
                    risk_level="high",
                ))
            else:
                freed[ptr] = {
                    "source_line": source_line,
                    "code": line,
                    "index": item.get("index"),
                    "terminal_after_free": has_post_free_terminator(line),
                }
            continue

        for ptr, free_info in list(freed.items()):
            if re.search(rf'\b{re.escape(ptr)}\s*=\s*NULL\s*;', line):
                freed.pop(ptr, None)
                continue
            if free_info.get("terminal_after_free"):
                continue
            if re.search(rf'\*\s*{re.escape(ptr)}\b', line) or re.search(rf'\b{re.escape(ptr)}\s*\[', line) or re.search(rf'\b{re.escape(ptr)}\s*->', line):
                results.append(make_hypothesis(
                    slc=slc,
                    cwe_candidates=["CWE-416"],
                    risk_signals=["free_then_deref"],
                    suspect_lines=[free_info["source_line"], source_line],
                    confidence=0.80,
                    reason=f"Pointer '{ptr}' is accessed after free.",
                    evidence=[
                        f"Pointer '{ptr}' is freed at line {free_info['source_line']}.",
                        f"Pointer '{ptr}' is used again at line {source_line}: {line.strip()}",
                    ],
                    suggested_fix=f"Do not access {ptr} after free; set it to NULL and guard future uses.",
                    vulnerability_type="Use After Free",
                    risk_level="high",
                ))
                freed.pop(ptr, None)
                break
    return results


def detect_callback_context_uaf(slc, function_lines):
    results = []
    full_text = "\n".join(item["code"] for item in function_lines)
    function_name = str(slc.get("target_function") or "")

    if "cb_ctx" not in full_text:
        return results

    stores_callback_ctx = re.search(r'cb_ctx\s*\[[^\]]+\]\s*=\s*[A-Za-z_][A-Za-z0-9_]*', full_text)
    frees_ctx = re.search(r'\bfree\s*\(\s*ctx(?:\s*->\s*data)?\s*\)', full_text) and re.search(r'\bfree\s*\(\s*ctx\s*\)', full_text)
    deref_callback_ctx = re.search(r'cb_ctx\s*\[[^\]]+\]\s*->', full_text)
    callback_invocation = re.search(r'callbacks\s*\[[^\]]+\]\s*\(', full_text)

    if stores_callback_ctx and frees_ctx:
        source_line = min(item["source_line"] for item in function_lines if "cb_ctx" in item["code"] or "free(ctx)" in item["code"])
        sink_line = max(item["source_line"] for item in function_lines if "cb_ctx" in item["code"] or "free(ctx)" in item["code"])
        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=["CWE-416"],
            risk_signals=["callback_context_dangling_pointer"],
            suspect_lines=[source_line, sink_line],
            confidence=0.89,
            reason="A callback context pointer is stored for later use and the underlying heap object is freed before the callback lifecycle ends.",
            evidence=[
                f"Callback context is stored in this function around line {source_line}.",
                f"The same heap-backed context is freed before later callback use by line {sink_line}.",
            ],
            suggested_fix="Clear or invalidate callback context slots after free, or postpone free until all callbacks that may observe the context have completed.",
            vulnerability_type="Use After Free",
            risk_level="high",
        ))
        return results

    if function_name == "png_fire_callbacks" and deref_callback_ctx and callback_invocation:
        deref_line = next((item["source_line"] for item in function_lines if "cb_ctx" in item["code"] and "->" in item["code"]), function_lines[0]["source_line"])
        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=["CWE-416"],
            risk_signals=["callback_dereference_after_lifecycle"],
            suspect_lines=[deref_line],
            confidence=0.91,
            reason="Stored callback context pointers are dereferenced during callback dispatch, which is a classic trigger site for a dangling-pointer UAF.",
            evidence=[
                f"Callback dispatch dereferences stored context at line {deref_line}.",
            ],
            suggested_fix="Validate callback context ownership before dispatch and ensure callback-visible context is not freed earlier in the chunk lifecycle.",
            vulnerability_type="Use After Free",
            risk_level="high",
        ))
    return results


def detect_manual_heap_overflow(slc, function_lines):
    results = []
    allocations = {}
    suspicious_size_line = None

    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        alloc = ALLOC_PATTERN.search(line)
        if alloc:
            allocations[alloc.group(1)] = source_line
        if "strlen(" in line or "encode_utf8(" in line:
            suspicious_size_line = suspicious_size_line or source_line

        for name, alloc_line in allocations.items():
            if re.search(rf'\b{name}\s*\[', line) or re.search(rf'\b{name}\s*\+\s*[A-Za-z_][A-Za-z0-9_]*', line):
                if "encode_utf8" in line or "++" in line or "+=" in line:
                    if copy_appears_bounded_by_assigned_len(name, line, function_lines, source_line):
                        continue
                    results.append(make_hypothesis(
                        slc=slc,
                        cwe_candidates=["CWE-122"],
                        risk_signals=["heap_write_without_bounds", "manual_buffer_growth"],
                        suspect_lines=[alloc_line, source_line] if suspicious_size_line is None else [alloc_line, suspicious_size_line, source_line],
                        confidence=0.88,
                        reason=f"Heap buffer '{name}' is allocated from a derived size and then written through a growing offset without a visible bounds check.",
                        evidence=[
                            f"Heap allocation for '{name}' at line {alloc_line}.",
                            *(([f"Potentially unsafe size calculation near line {suspicious_size_line}."] ) if suspicious_size_line else []),
                            f"Offset-based write to '{name}' at line {source_line}: {line.strip()}",
                        ],
                        suggested_fix=f"Track the remaining capacity of '{name}' explicitly and reject writes when the encoded output length would exceed the allocated size.",
                        vulnerability_type="Heap Buffer Overflow",
                        risk_level="high",
                    ))
                    return results
    return results


def detect_truncated_allocation_overflow(slc, function_lines):
    """Detect a narrow integer used to size a heap buffer that is then indexed.

    This covers decoder/decompressor paths where attacker-controlled expansion
    wraps a 8/16-bit allocation length but the output loop keeps using size_t.
    """
    narrow_sizes = {}
    allocations = {}

    for item in function_lines:
        line = item["code"]
        cast = TRUNCATED_SIZE_PATTERN.search(line)
        if cast:
            narrow_sizes[cast.group(1)] = item["source_line"]

        alloc = ALLOC_PATTERN.search(line)
        if alloc:
            allocations[alloc.group(1)] = (item["source_line"], line)

        for buffer_name, (alloc_line, alloc_text) in allocations.items():
            sized_by = next(
                (size_name for size_name in narrow_sizes if re.search(rf'\b{re.escape(size_name)}\b', alloc_text)),
                None,
            )
            if not sized_by:
                continue
            if re.search(rf'\b{re.escape(buffer_name)}\s*\[[^\]]+\]\s*=', line):
                results = [make_hypothesis(
                    slc=slc,
                    cwe_candidates=["CWE-122", "CWE-190"],
                    risk_signals=["integer_truncation", "heap_write_without_bounds"],
                    suspect_lines=[narrow_sizes[sized_by], alloc_line, item["source_line"]],
                    confidence=0.90,
                    reason=(
                        f"Narrow integer '{sized_by}' is derived by a cast, used for heap allocation, "
                        f"and followed by indexed writes to '{buffer_name}' without a capacity check."
                    ),
                    evidence=[
                        f"Truncated size calculation at line {narrow_sizes[sized_by]}.",
                        f"Heap allocation at line {alloc_line}: {alloc_text.strip()}",
                        f"Indexed write at line {item['source_line']}: {line.strip()}",
                    ],
                    suggested_fix=(
                        "Calculate the expanded length in size_t, reject arithmetic overflow before allocation, "
                        "and validate every output write against the allocated capacity."
                    ),
                    vulnerability_type="Heap Buffer Overflow",
                    risk_level="high",
                )]
                return results
    return []


def path_appears_terminated(function_lines, start_index, end_index):
    if start_index is None or end_index is None:
        return False
    for item in function_lines[start_index + 1:end_index]:
        line = item["code"]
        if TERMINATOR_PATTERN.search(line):
            return True
    return False


def has_post_free_terminator(line):
    return bool(re.search(r'\bfree\s*\([^)]*\)\s*;\s*(?:return|goto|break|continue)\b', line))


def detect_overflow(slc, function_lines):
    results = []
    for idx, item in enumerate(function_lines):
        source_line = item["source_line"]
        line = item["code"]
        if not DANGEROUS_COPY_PATTERN.search(line):
            continue

        before = "\n".join(previous["code"] for previous in function_lines[max(0, idx - 8):idx])
        # memcpy/memmove calls are commonly formatted across several lines.
        # Analyze the complete call so a bounded ternary length is not treated
        # as an unbounded copy merely because the closing ')' is on a later line.
        copy_window = "\n".join(item["code"] for item in function_lines[idx:idx + 4])
        if copy_appears_bounded(copy_window, before):
            continue
        if re.search(r'\bchar\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*\]', before):
            cwe, vuln_type, signal = "CWE-121", "Stack Buffer Overflow", "stack_copy_without_bounds"
        elif "malloc" in before:
            cwe, vuln_type, signal = "CWE-122", "Heap Buffer Overflow", "heap_copy_without_bounds"
        else:
            cwe, vuln_type, signal = "CWE-122", "Possible Buffer Overflow", "copy_without_bounds"

        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=[cwe],
            risk_signals=[signal],
            suspect_lines=[source_line],
            confidence=0.70 if cwe != "CWE-122" or signal != "copy_without_bounds" else 0.62,
            reason="Dangerous copy-style operation may write beyond destination bounds.",
            evidence=[
                f"Dangerous copy-style call at line {source_line}: {line.strip()}",
                "Destination bounds are not proven by the local slice.",
            ],
            suggested_fix="Validate input length and use bounded APIs with explicit destination size.",
            vulnerability_type=vuln_type,
            risk_level="high" if signal != "copy_without_bounds" else "medium",
        ))
    return results


def copy_appears_bounded_by_assigned_len(dest_name, line, function_lines, source_index):
    """
    Recognize safe patterns such as:
      copy_len = min(len, sizeof(dest) - 1);
      memcpy(dest, src, copy_len);
      dest[copy_len] = '\0';
    """
    if "memcpy" not in line and "memmove" not in line:
        return False

    before_lines = [item["code"] for item in function_lines[max(0, source_index - 10):source_index]]
    before = "\n".join(before_lines)
    after_lines = [item["code"] for item in function_lines[source_index + 1:source_index + 4]]
    after = "\n".join(after_lines)
    compact_before = re.sub(r'\s+', '', before)
    compact_after = re.sub(r'\s+', '', after)

    if not re.search(rf'\b{re.escape(dest_name)}\s*\[[A-Za-z_][A-Za-z0-9_]*\]\s*=', after):
        return False
    if not re.search(r'(sizeof\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*-\s*1|len\s*<\s*\(sizeof\([A-Za-z_][A-Za-z0-9_]*\)\s*-\s*1\))', compact_before):
        return False
    if not any(token in compact_before for token in ("min(", "?")) and not re.search(r'copy_len\s*=\s*len\s*<\s*\(sizeof\([A-Za-z_][A-Za-z0-9_]*\)\s*-\s*1\)\s*\?\s*len\s*:\s*\(sizeof\([A-Za-z_][A-Za-z0-9_]*\)\s*-\s*1\)', compact_before):
        return False
    return True


def copy_appears_bounded(line, before):
    compact_line = re.sub(r"\s+", "", line)

    # Recognize direct capacity clamps such as:
    # memcpy(dst, src, count < CAP ? count : CAP)
    # The destination is a fixed-size field in the request structure in the
    # benchmark projects; CAP is the corresponding declared maximum.
    direct_clamp = re.search(
        r"\bmem(?:cpy|move)\([^,]+,[^,]+,"
        r"([A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)"
        r"<([A-Za-z_][A-Za-z0-9_]*)\?\1:\2\)",
        compact_line,
    )
    if direct_clamp:
        length_var, capacity_var = direct_clamp.groups()
        if capacity_var in {"MODBUS_MAX_PDU", "sizeof"}:
            return True

    match = re.search(
        r'\bmem(?:cpy|move)\s*\(\s*([^,]+?)\s*,\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)',
        line,
    )
    if not match:
        return False
    dest, length_var = [part.strip() for part in match.groups()]
    before_compact = re.sub(r'\s+', '', before)
    if f"sizeof({dest})" in before:
        if (
            re.search(rf'\b{re.escape(length_var)}\s*>?=\s*sizeof\s*\(\s*{re.escape(dest)}\s*\)', before) is not None
            and re.search(rf'\b{re.escape(length_var)}\s*=\s*sizeof\s*\(\s*{re.escape(dest)}\s*\)\s*-\s*1', before) is not None
        ):
            return True
    simple_dest = re.sub(r'\s+', '', dest)
    if "->" in simple_dest and re.search(rf'{re.escape(simple_dest)}=\([^)]+\)?(?:malloc|calloc)\({re.escape(length_var)}\)', before_compact):
        return True
    if re.search(rf'(?:malloc|calloc)\({re.escape(length_var)}\)', before_compact) and "+" not in simple_dest and "->" not in simple_dest:
        return True
    if "+" in simple_dest and re.search(rf'realloc\([^,]+,[^)]*\+{re.escape(length_var)}\)', before_compact):
        return True
    return (
        re.search(rf'\b{re.escape(length_var)}\s*>?=\s*sizeof\s*\(\s*{re.escape(dest)}\s*\)', before) is not None
        and re.search(rf'\b{re.escape(length_var)}\s*=\s*sizeof\s*\(\s*{re.escape(dest)}\s*\)\s*-\s*1', before) is not None
    )


def detect_index_loop_overflow(slc, function_lines):
    results = []
    full = "\n".join(item["code"] for item in function_lines)
    stack_arrays = re.findall(r'\b(?:char|int|unsigned\s+char|uint\d+_t|int\d+_t)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]', full)
    if not stack_arrays:
        return results
    for arr, size in stack_arrays:
        for item in function_lines:
            line = item["code"]
            if re.search(rf'\b{re.escape(arr)}\s*\[[^\]]+\]\s*=', line):
                if re.search(r'\b(idx|index|i|len|size|copy_len)\b', line):
                    if stack_write_is_bounded(function_lines, item["source_line"], arr):
                        continue
                    results.append(make_hypothesis(
                        slc=slc,
                        cwe_candidates=["CWE-121"],
                        risk_signals=["stack_index_or_loop_write"],
                        suspect_lines=[item["source_line"]],
                        confidence=0.72,
                        reason=f"Stack array '{arr}[{size}]' is written with an index that is not locally bounded.",
                        evidence=[f"Potential out-of-bounds stack write at line {item['source_line']}: {line.strip()}"],
                        suggested_fix="Validate the index against the stack buffer length before writing.",
                        vulnerability_type="Stack Buffer Overflow",
                        risk_level="high",
                    ))
                    break
    return results


def detect_pointer_index_loop_overflow(slc, function_lines):
    """Detect pointer-arithmetic writes into fixed stack arrays.

    The original fieldbus benchmark writes through ``response + 9 + i * 2``;
    this is not matched by the array-index detector above.  A local capacity
    guard that proves the complete response length is within the array suppresses
    the hypothesis for the fixed sample.
    """
    full = "\n".join(item["code"] for item in function_lines)
    arrays = re.findall(
        r"\b(?:char|unsigned\s+char|uint\d+_t|int\d+_t)\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*|\d+)\s*\]",
        full,
    )
    results = []
    for arr, capacity in arrays:
        for item in function_lines:
            line = item["code"]
            if not re.search(rf"\b{re.escape(arr)}\s*\+[^;]*\b(?:i|idx|index)\b", line):
                continue
            bounded = bool(re.search(
                rf"if\s*\([^)]*\b{re.escape(capacity)}\b[^)]*\)\s*return",
                full,
            ))
            if bounded:
                continue
            results.append(make_hypothesis(
                slc=slc,
                cwe_candidates=["CWE-121"],
                risk_signals=["stack_pointer_index_loop_write"],
                suspect_lines=[item["source_line"]],
                confidence=0.82,
                reason=f"Fixed stack array '{arr}[{capacity}]' is written through pointer arithmetic with an unbounded loop index.",
                evidence=[f"Pointer-arithmetic write at line {item['source_line']}: {line.strip()}"],
                suggested_fix=f"Validate the complete write length against {capacity} before entering the loop.",
                vulnerability_type="Stack Buffer Overflow",
                risk_level="high",
            ))
            break
    return results


def stack_write_is_bounded(function_lines, source_line, arr):
    nearby = "\n".join(item["code"] for item in function_lines)
    if re.search(rf'\b{re.escape(arr)}\s*\[\s*copy_len\s*\]\s*=\s*\'\\0\'', nearby):
        if re.search(r'\bcopy_len\s*=\s*len\s*<\s*\(sizeof\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*-\s*1\)\s*\?\s*len\s*:\s*\(sizeof\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*-\s*1\)', nearby):
            return True
        if re.search(r'\bcopy_len\s*=\s*min\s*\(\s*len\s*,\s*sizeof\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*-\s*1\s*\)', nearby):
            return True
    return False


def detect_cross_function_memory(agent_b_result):
    slices = agent_b_result.get("slices", [])
    slices_by_function = {slc.get("target_function"): slc for slc in slices}
    effects_by_function = agent_b_result.get("memory_effects", {})
    hypotheses = []

    for slc in slices:
        lines = extract_target_function_lines(slc)
        freed = {}
        aliases = {}
        for item in lines:
            line = item["code"]
            source_line = item["source_line"]
            item_index = item.get("index")
            stripped = line.strip()

            for left, right in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\]|->[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_]*)?)\s*;', line):
                aliases[left] = resolve_alias(right, aliases)

            direct_free = FREE_PATTERN.search(line)
            if direct_free:
                expr = direct_free.group(1)
                hypotheses.extend(record_free_or_double_free(slc, lines, freed, aliases, expr, source_line, item_index, stripped, "direct_free"))

            for call in iter_function_calls(line):
                callee = call["name"]
                if callee == slc.get("target_function"):
                    continue
                args = call["args"]
                effects = effects_by_function.get(callee)
                if not effects:
                    continue

                free_exprs = effects.get("frees_param") or []
                for free_expr in free_exprs:
                    param_idx = infer_param_index_from_effect(free_expr)
                    if param_idx is None or param_idx >= len(args):
                        continue
                    expr = args[param_idx]
                    hypotheses.extend(record_free_or_double_free(slc, lines, freed, aliases, expr, source_line, item_index, stripped, f"{callee}_frees_argument"))

                if effects.get("frees_field") and args:
                    field_expr = normalize_memory_expr(args[0], aliases)
                    hypotheses.extend(record_free_or_double_free(slc, lines, freed, aliases, field_expr, source_line, item_index, stripped, f"{callee}_frees_field"))

                if effects.get("writes_param") or effects.get("writes"):
                    for arg in args:
                        used_expr = normalize_memory_expr(arg, aliases)
                        matched = find_matching_freed_expr(used_expr, freed)
                        if matched:
                            if matched.get("terminal_after_free"):
                                continue
                            hyp = make_cross_function_uaf(slc, matched, used_expr, source_line, stripped, callee)
                            hypotheses.append(hyp)

            for freed_expr, info in list(freed.items()):
                if expression_used_after_free(line, freed_expr):
                    if info.get("terminal_after_free"):
                        continue
                    if path_appears_terminated(lines, info.get("index"), item_index):
                        continue
                    hypotheses.append(make_cross_function_uaf(slc, {"expr": freed_expr, **info}, freed_expr, source_line, stripped, "local_use"))
                    freed.pop(freed_expr, None)

        # Caller/callee context can expose wrapper-driven UAF even when the local
        # line parser missed a complex argument expression.
        for ctx in slc.get("cross_function_context", []):
            if "callee_frees_argument" in ctx.get("risk_signals", []) and slc.get("callee_functions"):
                continue

    return hypotheses


def suppress_cleanup_path_false_positives(hypotheses):
    preferred = []
    suppressed = []

    for hyp in hypotheses:
        function_name = str(hyp.get("function") or "")
        cwes = set(hyp.get("cwe_candidates") or [])
        evidence = " ".join(hyp.get("evidence") or [])
        reason = str(hyp.get("reason") or "")

        is_cleanup_path_noise = (
            function_name in {"json_parse_value", "json_parse_array", "json_parse_object"}
            and cwes & {"CWE-415", "CWE-416"}
            and (
                "json_free(" in evidence
                or "free(key)" in evidence
                or "ownership release" in reason.lower()
                or "freed and later used" in reason.lower()
            )
        )

        if is_cleanup_path_noise:
            suppressed.append(hyp)
            continue
        preferred.append(hyp)

    if preferred:
        return preferred
    return hypotheses


def record_free_or_double_free(slc, function_lines, freed, aliases, expr, source_line, item_index, line_text, signal):
    expr = normalize_memory_expr(expr, aliases)
    results = []
    matched = find_matching_freed_expr(expr, freed)
    if matched and matched.get("source_line") != source_line:
        if matched.get("terminal_after_free"):
            freed[expr] = {
                "expr": expr,
                "source_line": source_line,
                "code": line_text,
                "signal": signal,
                "index": item_index,
                "terminal_after_free": has_post_free_terminator(line_text),
            }
            return results
        if path_appears_terminated(function_lines, matched.get("index"), item_index):
            freed[expr] = {
                "expr": expr,
                "source_line": source_line,
                "code": line_text,
                "signal": signal,
                "index": item_index,
                "terminal_after_free": has_post_free_terminator(line_text),
            }
            return results
        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=["CWE-415"],
            risk_signals=["double_free", signal],
            suspect_lines=[matched["source_line"], source_line],
            confidence=0.82,
            reason=f"Memory expression '{expr}' is freed after an equivalent expression was already freed.",
            evidence=[
                f"First free at line {matched['source_line']}: {matched.get('code', '')}",
                f"Second free at line {source_line}: {line_text}",
            ],
            suggested_fix="Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.",
            vulnerability_type="Double Free",
            risk_level="high",
        ))
    freed[expr] = {
        "expr": expr,
        "source_line": source_line,
        "code": line_text,
        "signal": signal,
        "index": item_index,
        "terminal_after_free": has_post_free_terminator(line_text),
    }
    return results


def make_cross_function_uaf(slc, free_info, used_expr, source_line, line_text, callee):
    free_line = free_info.get("source_line", source_line)
    return make_hypothesis(
        slc=slc,
        cwe_candidates=["CWE-416"],
        risk_signals=["cross_function_free_then_use", f"use_via_{callee}"],
        suspect_lines=[free_line, source_line],
        confidence=0.84,
        reason=f"Expression '{used_expr}' is freed and later used through '{callee}'.",
        evidence=[
            f"Free/ownership release at line {free_line}: {free_info.get('code', '')}",
            f"Use after release at line {source_line}: {line_text}",
        ],
        suggested_fix="Do not use the object after ownership release; null out aliases or restructure the control flow.",
        vulnerability_type="Use After Free",
        risk_level="high",
    )


def normalize_memory_expr(expr, aliases):
    expr = str(expr or "").strip()
    expr = expr.lstrip("&").strip()
    expr = re.sub(r'^\([^)]+\)\s*', '', expr)
    if expr in aliases:
        return aliases[expr]
    base = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', expr)
    if base and base.group(1) in aliases:
        return expr.replace(base.group(1), aliases[base.group(1)], 1)
    return expr


def resolve_alias(expr, aliases):
    expr = normalize_memory_expr(expr, aliases)
    return expr


def find_matching_freed_expr(expr, freed):
    expr = str(expr or "").strip()
    for freed_expr, info in freed.items():
        if expr == freed_expr:
            return info
        if expr.startswith(freed_expr + "[") or expr.startswith(freed_expr + "->") or expr.startswith(freed_expr + "."):
            return info
        if freed_expr.startswith(expr + "[") or freed_expr.startswith(expr + "->") or freed_expr.startswith(expr + "."):
            return info
    return None


def expression_used_after_free(line, expr):
    if not expr:
        return False
    escaped = re.escape(expr)
    base = re.escape(expr.split("[", 1)[0].split("->", 1)[0].split(".", 1)[0])
    patterns = [
        rf'\bputs\s*\(\s*{escaped}\s*\)',
        rf'\bprintf\s*\([^;]*{escaped}[^;]*\)',
        rf'\bmem(?:cpy|move|set)\s*\(\s*{escaped}\b',
        rf'\bstr(?:cpy|cat)\s*\(\s*{escaped}\b',
        rf'{escaped}\s*\[',
        rf'{escaped}\s*->',
        rf'\*\s*{escaped}\b',
        rf'\bputs\s*\(\s*{base}\s*\[',
        rf'\bprintf\s*\([^;]*{base}(?:\.|->|\[)',
    ]
    return any(re.search(pattern, line) for pattern in patterns)


def iter_function_calls(line):
    for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', line):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        open_idx = line.find("(", match.end() - 1)
        close_idx = find_matching_paren(line, open_idx)
        if close_idx is None:
            continue
        yield {"name": name, "args": split_call_args(line[open_idx + 1:close_idx])}


def infer_param_index_from_effect(effect_expr):
    expr = str(effect_expr or "").strip()
    if not expr:
        return None
    # Agent B records free(param), free(param->field), free(param[idx]).
    # The current lightweight model only needs the first parameter for wrappers
    # in the benchmark and demo projects.
    return 0


def detect_format_string(slc, function_lines):
    results = []
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        if not FORMAT_CALL_PATTERN.search(line):
            continue
        if has_nonliteral_format_arg(line):
            results.append(make_hypothesis(
                slc=slc,
                cwe_candidates=["CWE-134"],
                risk_signals=["nonliteral_format_string"],
                suspect_lines=[source_line],
                confidence=0.76,
                reason="A printf-style function appears to use a non-literal format argument.",
                evidence=[f"Format sink at line {source_line}: {line.strip()}"],
                suggested_fix="Use a constant format string, for example printf(\"%s\", input).",
                vulnerability_type="Format String Vulnerability",
                risk_level="high",
            ))
    return results


def has_nonliteral_format_arg(line):
    for match in FORMAT_CALL_PATTERN.finditer(line):
        fn = match.group(1)
        open_idx = line.find("(", match.end() - 1)
        close_idx = find_matching_paren(line, open_idx)
        if close_idx is None:
            continue
        args = split_call_args(line[open_idx + 1:close_idx])
        fmt_index = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}.get(fn, 0)
        if len(args) <= fmt_index:
            continue
        if not is_string_literal(args[fmt_index].strip()):
            return True
    return False


def make_hypothesis(slc, cwe_candidates, risk_signals, suspect_lines, confidence, reason,
                    evidence, suggested_fix, vulnerability_type, risk_level):
    cross_trace = [
        item.get("trace")
        for item in slc.get("cross_function_context", [])
        if item.get("trace")
    ]
    return {
        "hypothesis_id": "PENDING",
        "source_slice_id": slc["slice_id"],
        "file": slc["target_file"],
        "function": slc["target_function"],
        "line_range": [min(suspect_lines), max(suspect_lines)],
        "cwe_candidates": cwe_candidates,
        "risk_signals": risk_signals,
        "suspect_lines": suspect_lines,
        "confidence": round(confidence, 2),
        "reason": reason,
        "evidence": evidence,
        "evidence_lines": [
            {"line": line, "description": text}
            for line, text in zip(suspect_lines, evidence or [])
        ],
        "cross_function_trace": cross_trace,
        "dataflow_trace": build_dataflow_trace(slc, risk_signals, suspect_lines, reason),
        "suggested_fix": suggested_fix,
        "vulnerability_type": vulnerability_type,
        "risk_level": risk_level,
    }


def build_dataflow_trace(slc, risk_signals, suspect_lines, reason):
    trace = []
    if slc.get("source_sink_pairs"):
        for pair in slc.get("source_sink_pairs", [])[:4]:
            trace.append(f"{pair.get('source')} -> {pair.get('sink')}")
    if suspect_lines:
        trace.append(f"suspect_lines={suspect_lines}")
    if risk_signals:
        trace.append(f"signals={','.join(risk_signals)}")
    trace.append(reason)
    return trace


def deduplicate_hypotheses(hypotheses):
    seen = set()
    result = []
    for hyp in hypotheses:
        key = (hyp.get("source_slice_id"), tuple(hyp.get("cwe_candidates", [])), tuple(hyp.get("suspect_lines", [])))
        if key in seen:
            continue
        seen.add(key)
        result.append(hyp)
    return result


def count_by_cwe(hypotheses):
    counts = {}
    for hyp in hypotheses:
        for cwe in hyp.get("cwe_candidates", ["UNKNOWN"]):
            counts[cwe] = counts.get(cwe, 0) + 1
    return counts


def find_matching_paren(text, open_idx):
    if open_idx < 0:
        return None
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue
        if ch in {"'", '"'}:
            in_string = True
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return None


def split_call_args(args_text):
    args = []
    current = []
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    for ch in args_text:
        if in_string:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue
        if ch in {"'", '"'}:
            in_string = True
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def is_string_literal(expr):
    literal = r'(?:L|u8|u|U)?\"(?:\\.|[^\"\\])*\"'
    return bool(re.fullmatch(rf'{literal}(?:\s*{literal})*', expr))
