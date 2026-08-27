import argparse
from pathlib import Path

from core.file_scanner import scan_source_files, scan_project_metadata_files
from core.json_utils import save_json, load_json
from core.integration_schema import to_backend_components, to_backend_vulnerabilities

from agents.agent_a_dependency import run_agent_a
from agents.agent_b_slicer import run_agent_b
from agents.agent_c_hypothesis import run_agent_c
from agents.agent_d_llm_audit import run_agent_d
from agents.agent_d_harness import run_agent_d as run_agent_e
from agents.agent_f_dynamic_evidence import run_agent_f
from agents.agent_g_final_report import run_agent_g


def run_pipeline(
    project_path,
    output_dir="outputs",
    harness_dir="harness_packages",
    validation_dir=None,
):
    project_path = Path(project_path).resolve()
    project_name = project_path.name
    output_dir = Path(output_dir).resolve()
    harness_dir = Path(harness_dir).resolve()

    print(f"[0/9] Project: {project_path}")

    print("[1/9] Scanning C/C++ source files and metadata files...")
    source_files = scan_source_files(str(project_path))
    metadata_files = scan_project_metadata_files(str(project_path))
    print(f"      Source files: {len(source_files)}")
    print(f"      Metadata files: {len(metadata_files)}")

    print("[2/9] Agent A: dependency risk identification...")
    agent_a_result = run_agent_a(source_files, metadata_files)
    save_json(agent_a_result, output_dir / "agent_a_components.json")
    save_json(to_backend_components(agent_a_result), output_dir / "agent_a_backend_components.json")

    print("[3/9] Agent B: semantic slicing...")
    agent_b_result = run_agent_b(source_files)
    save_json(agent_b_result, output_dir / "agent_b_slices.json")

    print("[4/9] Agent C: vulnerability hypothesis generation...")
    agent_c_result = run_agent_c(agent_a_result, agent_b_result)
    save_json(agent_c_result, output_dir / "agent_c_hypotheses.json")

    print("[5/9] Agent D: LLM audit and cross-check...")
    agent_d_result = run_agent_d(agent_a_result, agent_b_result, agent_c_result)
    save_json(agent_d_result, output_dir / "agent_d_findings.json")
    save_json(agent_d_result, output_dir / "agent_c_findings.json")
    save_json(to_backend_vulnerabilities(agent_d_result), output_dir / "agent_c_backend_vulnerabilities.json")

    print("[6/9] Agent E: harness package generation and quality gate...")
    agent_e_result = run_agent_e(agent_d_result, harness_root=harness_dir, project_root=project_path)
    save_json(agent_e_result, output_dir / "agent_e_harness_packages.json")
    save_json(agent_e_result, output_dir / "agent_d_harness_packages.json")

    print("[7/9] Loading dynamic validation results...")
    validation_path = Path(validation_dir).resolve() if validation_dir else None
    afl_result, ebpf_log = load_dynamic_validation_artifacts(validation_path)
    asan_result = (
        load_json(validation_path / "asan_validation_results.json", default={})
        if validation_path
        else {}
    )

    if asan_result:
        print("      ASan results loaded: "
              f"{asan_result.get('summary', {}).get('confirmed_findings', 0)} confirmed")
    else:
        print("      No ASan results supplied; dynamic findings remain unverified.")

    print("[8/9] Agent F: dynamic evidence attribution...")
    agent_f_result = run_agent_f(
        agent_d_result=agent_d_result,
        agent_e_result=agent_e_result,
        afl_result=afl_result,
        ebpf_log=ebpf_log,
        asan_result=asan_result,
    )
    save_json(agent_f_result, output_dir / "agent_f_evidence_links.json")

    print("[9/9] Agent G: final risk decision and report...")
    agent_g_result = run_agent_g(
        project_name=project_name,
        agent_a_result=agent_a_result,
        agent_b_result=agent_b_result,
        agent_c_result=agent_c_result,
        agent_d_result=agent_d_result,
        agent_e_result=agent_e_result,
        agent_f_result=agent_f_result,
        output_dir=output_dir
    )
    save_json(agent_g_result, output_dir / "agent_g_final_decision.json")
    final_report = agent_g_result["final_report"]

    print("\n=== SENTINEL Seven-Agent Pipeline Finished ===")
    print(f"Project: {final_report['project_name']}")
    print(f"Overall Risk: {final_report['overall_risk']}")
    print(f"Components: {final_report['summary']['total_components']}")
    print(f"Hypotheses: {final_report['summary']['total_hypotheses']}")
    print(f"Static Findings: {final_report['summary']['total_static_findings']}")
    print(f"Harness Packages: {final_report['summary']['total_harness_packages']}")
    print(f"Confirmed Findings: {final_report['summary']['confirmed_findings']}")
    print(f"ASan Confirmed Findings: {final_report['summary'].get('asan_confirmed_findings', 0)}")
    print(f"Final JSON: {output_dir / 'final_report.json'}")
    print(f"Final MD: {output_dir / 'final_report.md'}")
    return final_report


def load_dynamic_validation_artifacts(validation_dir: Path | None):
    """
    Load real dynamic validation artifacts when available.

    Example/mock AFL++ and eBPF payloads are only used when explicitly enabled,
    otherwise they are treated as absent so they do not inflate the final risk.
    """
    if validation_dir is None:
        return {"crash_found": False}, {"events": []}

    afl_real = validation_dir / "afl_result.json"
    ebpf_real = validation_dir / "ebpf_log.json"

    afl_result = load_json(afl_real, default={"crash_found": False})
    ebpf_log = load_json(ebpf_real, default={"events": []})

    return afl_result, ebpf_log


def main():
    parser = argparse.ArgumentParser(description="SENTINEL - Seven-Agent Pipeline")
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", default="outputs")
    parser.add_argument("--harness", default="harness_packages")
    parser.add_argument(
        "--validation",
        default=None,
        help="Optional directory containing real ASan/AFL++/eBPF artifacts",
    )
    args = parser.parse_args()
    run_pipeline(args.project, args.output, args.harness, args.validation)


if __name__ == "__main__":
    main()
