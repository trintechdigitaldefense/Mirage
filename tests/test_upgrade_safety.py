from pathlib import Path


def test_upgrade_script_refuses_destructive_replacement_and_non_ff_reset():
    script = (Path(__file__).resolve().parents[1] / "start.sh").read_text(
        encoding="utf-8"
    )

    assert 'rm -rf "${ROOT}"' not in script
    assert "Refusing to replace existing non-Git directory" in script
    assert "Local branch has commits not present on origin" in script
    assert 'if [[ "${FORCE:-0}" == "1" ]]; then' in script
