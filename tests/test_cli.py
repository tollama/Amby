from app.cli import build_parser


def test_cli_exposes_core_subcommands() -> None:
    help_text = build_parser().format_help()

    assert "serve" in help_text
    assert "demo" in help_text
    assert "evidence" in help_text
    assert "predeploy" in help_text
    assert "control-plane" in help_text
