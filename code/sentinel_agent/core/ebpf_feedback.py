"""
eBPF Feedback Module - 动态修正LLM决策

当前轮fuzzing完成后,从eBPF事件中学习,为下一轮harness生成提供反馈。
"""
import json
from pathlib import Path
from typing import Dict, List, Any


class EbpfFeedbackCollector:
    """收集eBPF证据,生成修正建议供LLM参考"""

    def __init__(self):
        self.feedback_history = []

    def analyze_events(self, ebpf_events: List[Dict], llm_vuln_type: str) -> Dict[str, Any]:
        """
        分析eBPF事件并生成反馈

        Returns:
            {
                "needs_correction": bool,
                "detected_type": str,  # eBPF实际检测到的类型
                "confidence": float,    # 置信度
                "evidence": str,        # 证据描述(供LLM参考)
            }
        """
        if not ebpf_events:
            return {
                "needs_correction": False,
                "detected_type": None,
                "confidence": 0.0,
                "evidence": "No eBPF events captured"
            }

        # 统计事件类型分布
        event_counts = {}
        for evt in ebpf_events:
            event_name = evt.get("event") or evt.get("event_type") or "unknown"
            event_counts[event_name] = event_counts.get(event_name, 0) + 1

        # 映射到标准漏洞类型
        type_mapping = {
            "heap_overflow": "buffer_overflow",
            "stack_overflow": "buffer_overflow",
            "heap_overflow_suspected": "buffer_overflow",
            "stack_write_suspected": "buffer_overflow",
            "possible_buffer_overflow": "buffer_overflow",
            "use_after_free": "use_after_free",
            "use_after_free_suspected": "use_after_free",
            "double_free": "double_free",
            "double_free_suspected": "double_free",
        }

        detected_types = {}
        for event_name, count in event_counts.items():
            mapped_type = type_mapping.get(event_name)
            if mapped_type:
                detected_types[mapped_type] = detected_types.get(mapped_type, 0) + count

        if not detected_types:
            return {
                "needs_correction": False,
                "detected_type": None,
                "confidence": 0.0,
                "evidence": f"eBPF captured {len(ebpf_events)} events but none matched known vulnerability patterns"
            }

        # 取主要类型(出现次数最多)
        primary_type = max(detected_types.items(), key=lambda x: x[1])[0]
        confidence = detected_types[primary_type] / sum(detected_types.values())

        # 判断是否需要纠正
        needs_correction = primary_type != llm_vuln_type.lower()

        evidence_parts = [
            f"eBPF runtime monitoring captured {len(ebpf_events)} events:",
        ]
        for vtype, count in sorted(detected_types.items(), key=lambda x: -x[1]):
            evidence_parts.append(f"  - {vtype}: {count} events")

        if needs_correction:
            evidence_parts.append(
                f"\n⚠️  LLM static analysis suggested '{llm_vuln_type}', "
                f"but eBPF runtime evidence indicates '{primary_type}' with {confidence:.1%} confidence."
            )

        return {
            "needs_correction": needs_correction,
            "detected_type": primary_type,
            "confidence": confidence,
            "evidence": "\n".join(evidence_parts),
            "event_distribution": event_counts
        }

    def generate_prompt_enhancement(self, feedback: Dict[str, Any]) -> str:
        """
        生成用于增强LLM prompt的反馈文本

        用于下一轮harness生成时注入上下文
        """
        if not feedback.get("needs_correction"):
            return ""

        detected = feedback["detected_type"]
        confidence = feedback["confidence"]

        enhancement = f"""
[eBPF Runtime Feedback from Previous Round]
Our eBPF monitoring detected actual runtime behavior differs from static analysis:
- Detected Type: {detected} (confidence: {confidence:.1%})
- Evidence: {feedback.get('evidence', 'N/A')}

Please adjust your harness generation strategy to target {detected} specifically.
For buffer_overflow: focus on boundary conditions, large inputs, off-by-one scenarios.
For use_after_free: ensure freed pointers are still accessible in harness.
For double_free: trigger multiple free paths on same allocation.
"""
        return enhancement.strip()

    def save_feedback(self, vuln_id: str, feedback: Dict, output_dir: Path):
        """保存反馈历史供后续分析"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        feedback_file = output_dir / f"{vuln_id}_ebpf_feedback.json"
        feedback_file.write_text(json.dumps({
            "vuln_id": vuln_id,
            "feedback": feedback,
            "timestamp": str(Path(__file__).stat().st_mtime)
        }, indent=2), encoding="utf-8")


def get_ebpf_feedback_for_vuln(vuln_result: Dict) -> str:
    """
    从漏洞验证结果中提取eBPF反馈,返回可注入LLM prompt的文本

    Args:
        vuln_result: 包含ebpf_events和vuln_type的字典

    Returns:
        增强prompt的文本(如果无需纠正则返回空字符串)
    """
    collector = EbpfFeedbackCollector()

    ebpf_events = vuln_result.get("ebpf_events", [])
    llm_vuln_type = vuln_result.get("vuln_type", "unknown")

    feedback = collector.analyze_events(ebpf_events, llm_vuln_type)

    if feedback["needs_correction"]:
        return collector.generate_prompt_enhancement(feedback)

    return ""
