"""Проверки утилит без запросов к внешним сервисам."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["idor_messages.sh", "idor_profile.sh"])
def test_shell_requires_explicit_target(script):
    env = {k: v for k, v in os.environ.items() if k not in {"BASE_URL", "SESSION_TOKEN"}}
    result = subprocess.run(
        ["bash", str(ROOT / "poc" / script), "test-id"],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "BASE_URL" in result.stderr


@pytest.mark.parametrize("script", ["idor_messages.sh", "idor_profile.sh"])
def test_shell_safe_request_and_no_secret_output(script, tmp_path):
    # Подставной curl проверяет заголовок и возвращает только код, без сети.
    fake = tmp_path / "curl"
    fake.write_text(
        "#!/bin/bash\nset -eu\nheader=$(cat)\n"
        '[[ "$header" == "Cookie: x-session-token=test-secret" ]]\n'
        '[[ "$*" != *test-secret* ]]\n'
        'printf "Код HTTP: 403\\n"\n'
    )
    fake.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + ":" + os.environ["PATH"],
        "BASE_URL": "https://example.test",
        "SESSION_TOKEN": "test-secret",
    }
    result = subprocess.run(
        ["bash", str(ROOT / "poc" / script), "test-id"],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "Код HTTP: 403\n"
    assert "test-secret" not in result.stdout + result.stderr
    env["SESSION_TOKEN"] = "test-secret\nInjected: value"
    assert (
        subprocess.run(
            ["bash", str(ROOT / "poc" / script), "test-id"],
            check=False,
            env=env,
            capture_output=True,
        ).returncode
        != 0
    )


def test_email_script_has_no_default_remote_target():
    env = {k: v for k, v in os.environ.items() if k != "BASE_URL"}
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "poc/enum_emails.py"),
            "registered@example.test",
            "missing@example.test",
        ],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "BASE_URL" in result.stderr
