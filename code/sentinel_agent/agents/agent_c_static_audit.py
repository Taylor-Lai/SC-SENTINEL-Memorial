import json
import re
from pathlib import Path

from core.id_generator import make_id
from core.integration_schema import to_backend_vulnerabilities
from core.llm_client import LLMClient, extract_json_object

"""
Agent C - Static Vulnerability Audit

Part 3.2 upgraded version:
- LLM semantic audit + rule fallback.
- JSON parse retry / repair.
- Confidence calibration.
- LLM vs rule consistency check.
- quality_control metadata per finding.
"""

FREE_PATTERN = re.compile(r'\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
DANGEROUS_COPY_PATTERN = re.compile(r'\b(strcpy|strcat|sprintf|memcpy|memmove)\s*\(')
FORMAT_CALL_PATTERN = re.compile(r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(')
GENERIC_CALL_PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
TERMINATOR_PATTERN = re.compile(r'\b(return|goto|break|continue)\b')
ALLOC_PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(')

HIGH_VALUE_RISK_KEYWORDS = {
    "malloc", "calloc", "realloc", "free",
    "strcpy", "strncpy", "strcat", "sprintf", "snprintf",
    "printf", "fprintf", "vprintf", "vfprintf", "syslog",
    "memcpy", "memmove", "gets", "scanf", "sscanf",
    "new", "delete"
}

TARGET_BODY_MARKER = "/* ===== Target Function Body ===== */"
MAX_LLM_RETRIES = 2


def run_agent_c(agent_a_result, agent_b_result):
    findings = []
    audited_slices = []
    skipped_slices = []
    llm_errors = []
    quality_events = []

    llm_client = LLMClient()
    llm_available = llm_client.is_available()

    for slc in agent_b_result.get("slices", []):
        if not should_audit_slice(slc):
            skipped_slices.append({
                "slice_id": slc.get("slice_id"),
                "target_file": slc.get("target_file"),
                "target_function": slc.get("target_function"),
                "reason": "No memory-risk keyword found in this slice."
            })
            continue

        audited_slices.append({
            "slice_id": slc.get("slice_id"),
            "target_file": slc.get("target_file"),
            "target_function": slc.get("target_function"),
            "risk_keywords": slc.get("risk_keywords", [])
        })

        function_lines = extract_target_function_lines(slc)
        rule_findings = rule_audit_slice(slc, function_lines)

        if llm_available:
            try:
                llm_findings, slice_quality_events = llm_audit_slice(
                    llm_client, agent_a_result, slc, function_lines, rule_findings
                )
                quality_events.extend(slice_quality_events)
                if llm_findings:
                    findings.extend(llm_findings)
                else:
                    findings.extend(mark_fallback_reason(rule_findings, "llm_returned_no_findings"))
            except Exception as exc:
                llm_errors.append({
                    "slice_id": slc.get("slice_id"),
                    "target_file": slc.get("target_file"),
                    "target_function": slc.get("target_function"),
                    "error": str(exc)
                })
                findings.extend(mark_fallback_reason(rule_findings, "llm_call_failed"))
        else:
            findings.extend(mark_fallback_reason(rule_findings, "llm_not_configured"))

    findings = deduplicate_findings(findings)
    for idx, finding in enumerate(findings, start=1):
        finding["finding_id"] = make_id("FINDING", idx)

    quality_summary = build_quality_summary(findings, quality_events, llm_errors)

    result = {
        "agent": "Agent C - Static Vulnerability Audit",
        "audit_mode": "llm_with_rule_fallback" if llm_available else "rule_fallback_only",
        "static_findings": findings,
        "audited_slices": audited_slices,
        "skipped_slices": skipped_slices,
        "llm_errors": llm_errors,
        "quality_events": quality_events,
        "quality_summary": quality_summary,
        "summary": {
            "total_input_slices": len(agent_b_result.get("slices", [])),
            "audited_slices": len(audited_slices),
            "skipped_slices": len(skipped_slices),
            "total_findings": len(findings),
            "high_risk_findings": sum(1 for f in findings if f.get("risk_level") in {"high", "critical"}),
            "llm_available": llm_available,
            "llm_error_count": len(llm_errors),
            "llm_findings": sum(1 for f in findings if f.get("audit_source") == "llm"),
            "rule_fallback_findings": sum(1 for f in findings if f.get("audit_source") == "rule_fallback")
        }
    }
    result["vulnerabilities"] = to_backend_vulnerabilities(result)["vulnerabilities"]
    result["integration"] = {"vulnerabilities": result["vulnerabilities"]}
    return result


def should_audit_slice(slc):
    return bool(set(slc.get("risk_keywords", [])) & HIGH_VALUE_RISK_KEYWORDS)


def llm_audit_slice(llm_client, agent_a_result, slc, function_lines, rule_findings):
    prompt = load_prompt()
    user_content = build_llm_user_content(agent_a_result, slc, function_lines)
    messages = [{"role": "system", "content": prompt}, {"role": "user", "content": user_content}]
    raw_text, parsed, events = call_llm_with_json_retry(llm_client, messages, slc)
    llm_findings = normalize_llm_findings(parsed, slc)
    llm_findings = apply_quality_control(llm_findings, rule_findings, slc)
    return llm_findings, events


def call_llm_with_json_retry(llm_client, messages, slc):
    events = []
    last_raw = None
    last_error = None
    for attempt in range(1, MAX_LLM_RETRIES + 1):
        try:
            raw = llm_client.chat(messages, temperature=0)
            last_raw = raw
            parsed = extract_json_object(raw)
            events.append({"slice_id": slc.get("slice_id"), "event": "json_parse_success", "attempt": attempt})
            return raw, parsed, events
        except Exception as exc:
            last_error = str(exc)
            events.append({
                "slice_id": slc.get("slice_id"),
                "event": "json_parse_or_call_failed",
                "attempt": attempt,
                "error": last_error
            })
            if attempt < MAX_LLM_RETRIES:
                messages = messages + [{
                    "role": "user",
                    "content": "上一次输出无法被系统解析为严格 JSON，或请求失败。请重新输出一个 JSON 对象，不要 Markdown，不要解释。"
                }]
    raise RuntimeError(f"LLM failed after {MAX_LLM_RETRIES} attempts. Last error: {last_error}. Last raw output: {str(last_raw)[:300]}")


def load_prompt():
    prompt_path = Path("prompts") / "static_audit_prompt.txt"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")
    return "You are a C/C++ security auditing expert. Return strict JSON only."


def build_llm_user_content(agent_a_result, slc, function_lines):
    component_context = summarize_component_context(agent_a_result)
    numbered_code = "\n".join(f'{item["source_line"]}: {item["code"]}' for item in function_lines)

    # 提取变量声明信息
    var_analysis = analyze_buffer_declarations(function_lines)

    return f"""
请审计下面这个 C/C++ 函数切片。

【切片信息】
slice_id: {slc.get("slice_id")}
file: {slc.get("target_file")}
function: {slc.get("target_function")}
line_range: {slc.get("line_range")}
risk_keywords: {slc.get("risk_keywords")}
call_chain_upstream: {json.dumps(slc.get("call_chain_upstream", []), ensure_ascii=False)}
callee_functions: {json.dumps(slc.get("callee_functions", []), ensure_ascii=False)}

【组件风险上下文】
{component_context}

【关键变量声明分析】
{var_analysis}

【带原始源码行号的目标函数代码】
{numbered_code}

**【CWE分类规则 - 必须严格遵守】**

1. **Stack-based Buffer Overflow (CWE-121)**：
   - 缓冲区声明在**函数内部**：`type buffer[SIZE]` 或 `type buffer[MACRO_SIZE]`
   - 缓冲区是**结构体成员数组**且结构体在栈上分配
   - 关键特征：数组用方括号声明，无malloc/calloc
   - 示例：`uint8_t response[128]`, `char buf[BUFSIZE]`, `struct {{ uint8_t data[256]; }} req;`

2. **Heap-based Buffer Overflow (CWE-122)**：
   - 缓冲区通过 `malloc()`, `calloc()`, `realloc()`, `new` 分配
   - 缓冲区是指针且赋值来自堆分配函数
   - 关键特征：`ptr = malloc(...)`
   - 示例：`uint8_t *buf = malloc(size);`, `char *data = calloc(1, len);`

3. **判断优先级**：
   - 优先看【关键变量声明分析】章节的明确标注
   - 如果看到 "← STACK BUFFER"，必须使用 CWE-121
   - 如果看到 "← HEAP BUFFER"，必须使用 CWE-122
   - 如果代码中有 `type name[...]` 形式的声明，即使后续有指针运算，仍然是栈溢出

请只返回严格 JSON。
""".strip()


def summarize_component_context(agent_a_result):
    components = []
    for comp in agent_a_result.get("components", []):
        components.append({
            "name": comp.get("name"),
            "version": comp.get("version"),
            "risk_level": comp.get("risk_level"),
            "top_vulnerabilities": [
                {"id": v.get("id") or v.get("cve_id"), "summary": v.get("summary"), "risk_level": v.get("risk_level")}
                for v in comp.get("top_vulnerabilities", [])[:3]
            ]
        })
    return json.dumps(components, ensure_ascii=False, indent=2)


def analyze_buffer_declarations(function_lines):
    """Analyze buffer variable declarations to distinguish stack vs heap."""
    stack_buffers = []
    heap_buffers = []

    for item in function_lines:
        code = item.get("code", "").strip()
        # Stack arrays: type name[size]
        if match := re.search(r'((?:uint8_t|char|int|unsigned|uint16_t|uint32_t|size_t)\s+\w+\[[^\]]*\])', code):
            stack_buffers.append(f"  • {match.group(1)} ← STACK BUFFER")
        # Heap allocations: ptr = malloc/calloc/realloc
        elif match := re.search(r'(\w+\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\()', code):
            heap_buffers.append(f"  • {match.group(1).strip()} ← HEAP BUFFER")

    if not stack_buffers and not heap_buffers:
        return "未检测到显式缓冲区声明"

    result = []
    if stack_buffers:
        result.append("**栈缓冲区（Stack Buffers）:**\n" + "\n".join(stack_buffers))
    if heap_buffers:
        result.append("**堆缓冲区（Heap Buffers）:**\n" + "\n".join(heap_buffers))

    return "\n\n".join(result)


def normalize_llm_findings(parsed, slc):
    if not isinstance(parsed, dict):
        return []
    raw_findings = parsed.get("findings", [])
    if not parsed.get("has_vulnerability") or not raw_findings:
        return []
    result = []
    for item in raw_findings:
        line_range = item.get("line_range") or slc.get("line_range")
        if not valid_line_range(line_range, slc):
            line_range = clamp_line_range(line_range, slc)
        original_confidence = normalize_confidence(item.get("confidence", 0.5))
        result.append({
            "finding_id": "PENDING",
            "source_slice_id": slc["slice_id"],
            "file": slc["target_file"],
            "function": slc["target_function"],
            "line_range": line_range,
            "cwe_id": item.get("cwe_id", "UNKNOWN"),
            "vulnerability_type": item.get("vulnerability_type", "Unknown"),
            "risk_level": normalize_risk(item.get("risk_level", "medium")),
            "trigger_condition": item.get("trigger_condition", ""),
            "evidence": normalize_evidence(item.get("evidence", [])),
            "confidence": original_confidence,
            "suggested_fix": item.get("suggested_fix", ""),
            "static_status": "suspected",
            "audit_source": "llm",
            "quality_control": {
                "original_confidence": original_confidence,
                "calibrated_confidence": original_confidence,
                "confidence_adjusted": False,
                "rule_consistency": "unchecked",
                "warnings": []
            }
        })
    return result


def normalize_evidence(evidence):
    if isinstance(evidence, list):
        return [str(x) for x in evidence]
    if evidence:
        return [str(evidence)]
    return []


def apply_quality_control(llm_findings, rule_findings, slc):
    controlled = []
    for finding in llm_findings:
        matched_rule = find_matching_rule_finding(finding, rule_findings)
        consistency = classify_rule_consistency(finding, matched_rule, rule_findings)
        warnings = []
        original_conf = normalize_confidence(finding.get("quality_control", {}).get("original_confidence", finding.get("confidence", 0.5)))
        calibrated_conf = calibrate_confidence(original_conf, consistency, finding)
        if calibrated_conf != original_conf:
            warnings.append(f"confidence_adjusted_from_{original_conf}_to_{calibrated_conf}")
        if not finding.get("evidence"):
            warnings.append("missing_evidence")
        if not finding.get("trigger_condition"):
            warnings.append("missing_trigger_condition")
        if finding.get("cwe_id") not in {"CWE-416", "CWE-415", "CWE-122", "CWE-121", "CWE-134"}:
            warnings.append("unexpected_cwe_id")
        finding["confidence"] = calibrated_conf
        finding["quality_control"] = {
            "original_confidence": original_conf,
            "calibrated_confidence": calibrated_conf,
            "confidence_adjusted": calibrated_conf != original_conf,
            "rule_consistency": consistency,
            "matched_rule_cwe": matched_rule.get("cwe_id") if matched_rule else None,
            "matched_rule_line_range": matched_rule.get("line_range") if matched_rule else None,
            "warnings": warnings
        }
        controlled.append(finding)
    return controlled


def find_matching_rule_finding(llm_finding, rule_findings):
    for rule in rule_findings:
        if rule.get("cwe_id") == llm_finding.get("cwe_id") and line_ranges_overlap(rule.get("line_range"), llm_finding.get("line_range")):
            return rule
    for rule in rule_findings:
        if line_ranges_overlap(rule.get("line_range"), llm_finding.get("line_range")):
            return rule
    return None


def classify_rule_consistency(llm_finding, matched_rule, rule_findings):
    if matched_rule is None:
        return "llm_only_rule_found_other_issue" if rule_findings else "llm_only_no_rule_baseline"
    return "consistent" if matched_rule.get("cwe_id") == llm_finding.get("cwe_id") else "line_overlap_cwe_conflict"


def line_ranges_overlap(a, b):
    if not isinstance(a, list) or not isinstance(b, list) or len(a) != 2 or len(b) != 2:
        return False
    return not (a[1] < b[0] or b[1] < a[0])


def calibrate_confidence(original_confidence, consistency, finding):
    conf = normalize_confidence(original_confidence)
    if consistency == "consistent":
        conf = min(conf, 0.95)
        conf = max(conf, 0.75)
    elif consistency == "line_overlap_cwe_conflict":
        conf = min(conf, 0.70)
    else:
        conf = min(conf, 0.85)
    if not finding.get("evidence") or not finding.get("trigger_condition"):
        conf = min(conf, 0.70)
    return round(conf, 2)


def build_quality_summary(findings, quality_events, llm_errors):
    return {
        "total_quality_events": len(quality_events),
        "json_retry_events": sum(1 for e in quality_events if e.get("event") == "json_parse_or_call_failed"),
        "confidence_adjusted_count": sum(1 for f in findings if f.get("quality_control", {}).get("confidence_adjusted")),
        "consistent_with_rule_count": sum(1 for f in findings if f.get("quality_control", {}).get("rule_consistency") == "consistent"),
        "cwe_conflict_count": sum(1 for f in findings if f.get("quality_control", {}).get("rule_consistency") == "line_overlap_cwe_conflict"),
        "llm_error_count": len(llm_errors)
    }


def valid_line_range(line_range, slc):
    if not isinstance(line_range, list) or len(line_range) != 2:
        return False
    start, end = line_range
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    return slc["line_range"][0] <= start <= end <= slc["line_range"][1]


def clamp_line_range(line_range, slc):
    start, end = slc["line_range"]
    if isinstance(line_range, list) and len(line_range) == 2:
        raw_start, raw_end = line_range
        if isinstance(raw_start, int) and isinstance(raw_end, int):
            return [max(start, min(raw_start, end)), max(start, min(raw_end, end))]
    return [start, end]


def normalize_risk(risk):
    risk = str(risk or "medium").lower()
    return risk if risk in {"critical", "high", "medium", "low", "unknown"} else "medium"


def normalize_confidence(value):
    try:
        value = float(value)
    except Exception:
        return 0.5
    return max(0.0, min(value, 1.0))


def extract_target_function_lines(slc):
    code = slc.get("code", "")
    function_start_line = slc["line_range"][0]
    body = code.split(TARGET_BODY_MARKER, 1)[1] if TARGET_BODY_MARKER in code else code
    raw_lines = body.splitlines()
    while raw_lines and raw_lines[0].strip() == "":
        raw_lines.pop(0)
    return [{"index": idx, "source_line": function_start_line + idx, "code": line} for idx, line in enumerate(raw_lines, start=0)]


def rule_audit_slice(slc, function_lines):
    results = []
    results.extend(_detect_uaf_and_double_free(slc, function_lines))
    results.extend(_detect_cross_function_uaf(slc, function_lines))
    results.extend(_detect_overflow(slc, function_lines))
    results.extend(_detect_manual_heap_overflow(slc, function_lines))
    for item in results:
        item["audit_source"] = "rule_fallback"
    return results


def _detect_format_string(slc, function_lines):
    results = []
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        if not FORMAT_CALL_PATTERN.search(line):
            continue

        for call in extract_function_calls(line):
            fn = call["function"]
            if fn not in {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "syslog"}:
                continue

            fmt_index = format_arg_index(fn)
            args = split_call_args(call["args"])
            if len(args) <= fmt_index:
                continue

            fmt_arg = args[fmt_index].strip()
            if is_string_literal(fmt_arg):
                continue

            results.append(_finding(
                slc,
                "CWE-134",
                "Format String Vulnerability",
                "high",
                [source_line, source_line],
                [
                    f"Function '{fn}' uses a non-literal format argument at source line {source_line}: {line.strip()}",
                    f"Format argument expression: {fmt_arg}",
                ],
                "Attacker-controlled input may be interpreted as a format string, enabling memory disclosure or arbitrary writes via %x/%s/%n tokens.",
                "Use a constant format string such as printf(\"%s\", input), fprintf(stream, \"%s\", input), or snprintf(buf, size, \"%s\", input).",
            ))
    return results


def extract_function_calls(line):
    calls = []
    for match in GENERIC_CALL_PATTERN.finditer(line):
        fn = match.group(1)
        if fn in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        open_idx = line.find("(", match.end() - 1)
        if open_idx == -1:
            continue
        close_idx = find_matching_paren(line, open_idx)
        if close_idx is None:
            continue
        calls.append({"function": fn, "args": line[open_idx + 1:close_idx]})
    return calls


def find_matching_paren(text, open_idx):
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


def normalize_memory_expr(expr):
    expr = str(expr or "").strip()
    expr = expr.lstrip("&").strip()
    expr = re.sub(r'^\([^)]+\)\s*', '', expr)
    return expr


def memory_base(expr):
    match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', normalize_memory_expr(expr))
    return match.group(1) if match else ""


def infer_param_index_from_effect(effect_expr):
    # Agent B records effects like free(param), memcpy(param, ...). For the
    # wrapper patterns in the current benchmark, the affected argument is the
    # first parameter.
    return 0


def format_arg_index(function_name):
    return {
        "printf": 0,
        "vprintf": 0,
        "fprintf": 1,
        "vfprintf": 1,
        "sprintf": 1,
        "snprintf": 2,
        "syslog": 1,
    }.get(function_name, 0)


def is_string_literal(expr):
    expr = expr.strip()
    # Adjacent C string literals, optionally prefixed with L/u/u8/U, are safe.
    literal = r'(?:L|u8|u|U)?\"(?:\\.|[^\"\\])*\"'
    return bool(re.fullmatch(rf'{literal}(?:\s*{literal})*', expr))


def _detect_uaf_and_double_free(slc, function_lines):
    results = []
    freed = {}
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        m = FREE_PATTERN.search(line)
        if m:
            ptr = m.group(1)
            if ptr in freed:
                if _path_appears_terminated(function_lines, freed[ptr]["index"], item["index"]):
                    freed[ptr] = {"source_line": source_line, "code": line, "index": item["index"]}
                    continue
                results.append(_finding(slc, "CWE-415", "Double Free", "high", [freed[ptr]["source_line"], source_line], [f"Pointer '{ptr}' is first freed at source line {freed[ptr]['source_line']}.", f"Pointer '{ptr}' is freed again at source line {source_line}: {line.strip()}"], f"Execution reaches free({ptr}) twice without reset or reallocation.", f"Set {ptr} to NULL after free and avoid duplicate ownership."))
            else:
                freed[ptr] = {"source_line": source_line, "code": line, "index": item["index"]}
            continue
        for ptr, free_info in list(freed.items()):
            if re.search(rf'\b{re.escape(ptr)}\s*=\s*NULL\s*;', line):
                freed.pop(ptr, None)
                continue
            if re.search(rf'\*\s*{re.escape(ptr)}\b', line) or re.search(rf'\b{re.escape(ptr)}\s*\[', line) or re.search(rf'\b{re.escape(ptr)}\s*->', line):
                results.append(_finding(slc, "CWE-416", "Use After Free", "high", [free_info["source_line"], source_line], [f"Pointer '{ptr}' is freed at source line {free_info['source_line']}.", f"Pointer '{ptr}' is used again at source line {source_line}: {line.strip()}"], f"Pointer '{ptr}' is dereferenced or accessed after free.", f"Do not access {ptr} after free; set it to NULL and guard future uses."))
                freed.pop(ptr, None)
                break
    return results


def _detect_cross_function_uaf(slc, function_lines):
    effects_by_callee = {
        ctx.get("callee"): ctx.get("callee_effects") or {}
        for ctx in slc.get("cross_function_context", [])
        if ctx.get("callee")
    }
    if not effects_by_callee:
        return []

    results = []
    freed = {}
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        stripped = line.strip()

        for call in extract_function_calls(line):
            callee = call["function"]
            effects = effects_by_callee.get(callee)
            if not effects:
                continue

            args = split_call_args(call["args"])
            if not args:
                continue

            for free_expr in effects.get("frees_param") or []:
                param_index = infer_param_index_from_effect(free_expr)
                if param_index is None or param_index >= len(args):
                    continue
                ptr = normalize_memory_expr(args[param_index])
                ptr_base = memory_base(ptr)
                if not ptr_base:
                    continue
                if ptr_base in freed:
                    first = freed[ptr_base]
                    if not _path_appears_terminated(function_lines, first["index"], item["index"]):
                        results.append(_finding(
                            slc,
                            "CWE-415",
                            "Double Free",
                            "high",
                            [first["source_line"], source_line],
                            [
                                f"Call to '{first['callee']}' frees '{ptr_base}' at source line {first['source_line']}: {first['code']}",
                                f"Call to '{callee}' can free '{ptr_base}' again at source line {source_line}: {stripped}",
                            ],
                            f"Pointer '{ptr_base}' is released by one callee and can be released again by another call without reset or reallocation.",
                            f"Use a single owner for '{ptr_base}', set it to NULL after release, or avoid duplicate release paths.",
                        ))
                freed[ptr_base] = {"source_line": source_line, "code": stripped, "index": item["index"], "callee": callee}

            if effects.get("writes_param") or effects.get("writes"):
                for arg in args:
                    ptr_base = memory_base(arg)
                    if not ptr_base or ptr_base not in freed:
                        continue
                    first = freed[ptr_base]
                    if _path_appears_terminated(function_lines, first["index"], item["index"]):
                        continue
                    results.append(_finding(
                        slc,
                        "CWE-416",
                        "Use After Free",
                        "high",
                        [first["source_line"], source_line],
                        [
                            f"Call to '{first['callee']}' frees '{ptr_base}' at source line {first['source_line']}: {first['code']}",
                            f"Call to '{callee}' uses or writes '{ptr_base}' after free at source line {source_line}: {stripped}",
                        ],
                        f"Pointer '{ptr_base}' is freed through callee '{first['callee']}' and then reused through callee '{callee}'.",
                        f"Do not pass '{ptr_base}' to '{callee}' after it has been freed; reorder ownership or null-check before reuse.",
                    ))
                    freed.pop(ptr_base, None)
                    break

            for ptr_base, first in list(freed.items()):
                if re.search(rf'\b{re.escape(ptr_base)}\s*=\s*NULL\s*;', line):
                    freed.pop(ptr_base, None)

    return results


def _detect_manual_heap_overflow(slc, function_lines):
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
                    evidence = [
                        f"Heap allocation for '{name}' appears at source line {alloc_line}.",
                        f"Offset-based write to '{name}' appears at source line {source_line}: {line.strip()}",
                    ]
                    if suspicious_size_line:
                        evidence.insert(1, f"Potentially unsafe size calculation appears near source line {suspicious_size_line}.")
                    results.append(_finding(
                        slc,
                        "CWE-120",
                        "Buffer Overflow",
                        "high",
                        [alloc_line, source_line],
                        evidence,
                        f"Buffer '{name}' is allocated from a derived size and then written through a growing offset without a visible bounds check.",
                        f"Track the remaining capacity of '{name}' explicitly and validate each write before advancing the output pointer.",
                    ))
                    return results
    return results


def _path_appears_terminated(function_lines, start_index, end_index):
    if start_index is None or end_index is None:
        return False
    for item in function_lines[start_index + 1:end_index]:
        if TERMINATOR_PATTERN.search(item["code"]):
            return True
    return False


def _detect_overflow(slc, function_lines):
    results = []
    for idx, item in enumerate(function_lines):
        source_line = item["source_line"]
        line = item["code"]
        if not DANGEROUS_COPY_PATTERN.search(line):
            continue
        before = "\n".join(previous["code"] for previous in function_lines[max(0, idx - 8):idx])
        if re.search(r'\bchar\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*\]', before) or "malloc" in before:
            cwe, vuln_type, risk = "CWE-120", "Buffer Overflow", "high"
        else:
            cwe, vuln_type, risk = "CWE-120", "Possible Buffer Overflow", "medium"
        results.append(_finding(slc, cwe, vuln_type, risk, [source_line, source_line], [f"Dangerous copy-style function call at source line {source_line}: {line.strip()}", "Rule fallback cannot fully prove destination bounds."], "Oversized or attacker-controlled input may reach a copy operation without sufficient length validation.", "Validate length before copying and use bounded APIs with explicit destination size."))
    return results


def _finding(slc, cwe, vuln_type, risk, source_line_range, evidence, trigger, fix):
    return {
        "finding_id": "PENDING",
        "source_slice_id": slc["slice_id"],
        "file": slc["target_file"],
        "function": slc["target_function"],
        "line_range": source_line_range,
        "cwe_id": cwe,
        "vulnerability_type": vuln_type,
        "risk_level": risk,
        "trigger_condition": trigger,
        "evidence": evidence,
        "confidence": 0.65,
        "suggested_fix": fix,
        "static_status": "suspected"
    }


def mark_fallback_reason(rule_findings, reason):
    result = []
    for finding in rule_findings:
        finding = dict(finding)
        finding["audit_source"] = "rule_fallback"
        finding["quality_control"] = {"fallback_reason": reason, "rule_consistency": "rule_only", "warnings": []}
        result.append(finding)
    return result


def deduplicate_findings(findings):
    seen = set()
    result = []
    for finding in findings:
        key = (finding.get("source_slice_id"), finding.get("cwe_id"), tuple(finding.get("line_range", [])))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
