from agents.agent_d_harness import make_makefile


def _profile():
    return {
        "source_entries": [
            {"src": "target.c", "obj": "target.o"},
            {"src": "other_main.c", "obj": "other_main.o"},
            {"src": "optional_sdk.c", "obj": "optional_sdk.o"},
        ],
        "include_dirs": ["."],
        "target_relpath": "target.c",
        "main_source_relpaths": ["target.c", "other_main.c"],
    }


def test_original_main_replay_compiles_only_target_translation_unit():
    makefile = make_makefile(
        {"file": "target.c"},
        {"argument_model": "original_main_file_arg"},
        build_profile=_profile(),
    )

    assert "target.o:" in makefile
    assert "asan: target.o harness_asan.o" in makefile
    assert "other_main.o:" not in makefile
    assert "optional_sdk.o:" not in makefile


def test_original_main_replay_includes_project_entrypoint_for_helper_finding():
    profile = _profile()
    profile["target_relpath"] = "helper.c"
    profile["source_entries"] = [
        {"src": "helper.c", "obj": "helper.o"},
        {"src": "main.c", "obj": "main.o"},
        {"src": "optional_sdk.c", "obj": "optional_sdk.o"},
    ]
    profile["main_source_relpaths"] = ["main.c"]

    makefile = make_makefile(
        {"file": "helper.c"},
        {"argument_model": "original_main_file_arg"},
        build_profile=profile,
    )

    assert "asan: helper.o main.o harness_asan.o" in makefile
    assert "main.o:" in makefile
    assert "optional_sdk.o:" not in makefile


def test_direct_function_build_excludes_other_program_entry_points():
    makefile = make_makefile(
        {"file": "target.c"},
        {"argument_model": "const_char_ptr"},
        build_profile=_profile(),
    )

    assert "target.o:" in makefile
    assert "optional_sdk.o:" in makefile
    assert "other_main.o:" not in makefile
