import io
import json
import sys
import types
import pytest

# We import the CLI module once here so monkeypatch can target its symbols.
import watermarking_cli as cli


# ---------------------------
# helpers / fixtures
# ---------------------------
@pytest.fixture()
def sample_pdf(tmp_path):
    p = tmp_path / "in.pdf"
    p.write_bytes(b"%PDF-1.4\n%EOF\n")
    return p


# ---------------------------
# methods
# ---------------------------
def test_methods_lists_registered(monkeypatch, capsys):
    # Fake a minimal registry that the CLI will print
    fake_methods = {
        "toy-eof": object(),
        "xmp-metadata": object(),
    }
    # Expose a METHODS-like object for the CLI
    monkeypatch.setattr(cli, "METHODS", fake_methods, raising=False)

    rc = cli.main(["methods"])
    out = capsys.readouterr().out

    # The CLI prints method names (one per line). We only assert names, not usage text.
    printed_names = {line.strip() for line in out.splitlines() if line.strip()}
    assert rc == 0
    assert printed_names >= set(fake_methods.keys())   # at least includes our two names

# ---------------------------
# explore
# ---------------------------
def test_explore_writes_json(monkeypatch, sample_pdf, tmp_path, capsys):
    # Stub explore_pdf to return a simple tree
    monkeypatch.setattr(cli, "explore_pdf", lambda pdf: {"id": "root", "type": "Document"})
    out = tmp_path / "tree.json"

    rc = cli.main(["explore", str(sample_pdf), "--out", str(out)])
    assert rc == 0 and out.exists()

    data = json.loads(out.read_text("utf-8"))
    assert data["type"] == "Document"


# ---------------------------
# embed
# ---------------------------
def test_embed_with_inline_secret_and_key(monkeypatch, sample_pdf, tmp_path, capsys):
    # Stub apply_watermark to avoid real PDF processing
    monkeypatch.setattr(cli, "apply_watermark", lambda **kw: b"%PDF-1.4\n% DUMMY\n%EOF\n")

    out = tmp_path / "out.pdf"
    rc = cli.main([
        "embed", str(sample_pdf), str(out),
        "--secret", "HELLO",
        "--key", "K",
    ])
    stdout = capsys.readouterr().out
    assert rc == 0 and out.exists()
    assert "Wrote watermarked PDF" in stdout


def test_embed_secret_from_file_and_key_from_stdin(monkeypatch, sample_pdf, tmp_path, capsys):
    monkeypatch.setattr(cli, "apply_watermark", lambda **kw: b"%PDF-1.4\n% DUMMY\n%EOF\n")

    secret_file = tmp_path / "s.txt"
    secret_file.write_text("FROM_FILE", encoding="utf-8")

    out = tmp_path / "o.pdf"

    # --key-stdin: simulate stdin providing the key
    monkeypatch.setattr(sys, "stdin", io.StringIO("KEY_FROM_STDIN\n"))

    rc = cli.main([
        "embed", str(sample_pdf), str(out),
        "--secret-file", str(secret_file),
        "--key-stdin",
    ])
    assert rc == 0 and out.exists()


def test_embed_key_prompt(monkeypatch, sample_pdf, tmp_path):
    monkeypatch.setattr(cli, "apply_watermark", lambda **kw: b"%PDF-1.4\n% DUMMY\n%EOF\n")
    # Simulate interactive getpass
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "PROMPTED_KEY")
    out = tmp_path / "o.pdf"

    rc = cli.main([
        "embed", str(sample_pdf), str(out),
        "--secret", "S",
        "--key-prompt",
    ])
    assert rc == 0 and out.exists()


# ---------------------------
# extract
# ---------------------------
def test_extract_prints_secret_to_stdout(monkeypatch, sample_pdf, capsys):
    monkeypatch.setattr(cli, "read_watermark", lambda **kw: "HELLO_OUT")
    rc = cli.main(["extract", str(sample_pdf), "--key", "K"])
    out = capsys.readouterr().out.strip()
    assert rc == 0 and out == "HELLO_OUT"


def test_extract_writes_secret_to_file(monkeypatch, sample_pdf, tmp_path, capsys):
    monkeypatch.setattr(cli, "read_watermark", lambda **kw: "FROM_FUNC")
    out = tmp_path / "secret.txt"
    rc = cli.main(["extract", str(sample_pdf), "--key", "K", "--out", str(out)])
    assert rc == 0 and out.read_text("utf-8") == "FROM_FUNC"


# ---------------------------
# error mapping (exit codes)
# ---------------------------
def test_extract_secret_not_found_maps_to_exit3(monkeypatch, sample_pdf, capsys):
    # Raise the exact exception type the CLI maps to code 3
    class SecretNotFound(cli.SecretNotFoundError): ...
    def boom(**kw): raise SecretNotFound("nothing here")
    monkeypatch.setattr(cli, "read_watermark", boom)

    rc = cli.main(["extract", str(sample_pdf), "--key", "K"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "secret not found" in err.lower()


def test_invalid_key_maps_to_exit4(monkeypatch, sample_pdf, capsys):
    class BadKey(cli.InvalidKeyError): ...
    def boom(**kw): raise BadKey("wrong key")
    monkeypatch.setattr(cli, "read_watermark", boom)

    rc = cli.main(["extract", str(sample_pdf), "--key", "K"])
    err = capsys.readouterr().err
    assert rc == 4
    assert "invalid key" in err.lower()


def test_value_error_maps_to_exit2(monkeypatch, sample_pdf, capsys):
    def boom(**kw): raise ValueError("bad args")
    monkeypatch.setattr(cli, "apply_watermark", lambda **kw: (_ for _ in ()).throw(ValueError("bad args")))
    rc = cli.main(["embed", str(sample_pdf), "out.pdf", "--secret", "S", "--key", "K"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error:" in err.lower()
