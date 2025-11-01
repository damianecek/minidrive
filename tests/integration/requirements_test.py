#!/usr/bin/env python3
"""Integration test exercising MiniDrive requirements."""
from __future__ import annotations

import argparse
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


def wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Server on {host}:{port} did not start within {timeout} seconds")


def run_client(client_bin: Path, endpoint: str, extra_args: list[str], input_data: str, workdir: Path) -> subprocess.CompletedProcess:
    cmd = [str(client_bin), endpoint, *extra_args]
    return subprocess.run(
        cmd,
        input=input_data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=workdir,
        check=False,
    )


def read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8") as f:
        return f.read()


def ensure_same_tree(local_dir: Path, remote_dir: Path) -> None:
    local_entries = sorted(p.relative_to(local_dir) for p in local_dir.rglob("*"))
    remote_entries = sorted(p.relative_to(remote_dir) for p in remote_dir.rglob("*"))
    assert local_entries == remote_entries, f"Directory mismatch: {local_entries} != {remote_entries}"
    for rel in local_entries:
        local_path = local_dir / rel
        remote_path = remote_dir / rel
        if local_path.is_file():
            assert remote_path.is_file(), f"Missing remote file {remote_path}"
            assert read_text(local_path) == read_text(remote_path), f"File content mismatch for {rel}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    args = parser.parse_args()

    server_bin = Path(args.server)
    client_bin = Path(args.client)

    with tempfile.TemporaryDirectory(prefix="minidrive_it_") as tmp:
        tmp_path = Path(tmp)
        server_root = tmp_path / "server_root"
        client_work = tmp_path / "client_work"
        sync_local = client_work / "sync_local"
        client_work.mkdir()
        server_root.mkdir()
        sync_local.mkdir(parents=True)

        # Prepare local files
        (client_work / "foo.txt").write_text("hello from minidrive\n", encoding="utf-8")
        (sync_local / "nested").mkdir(parents=True)
        (sync_local / "file_a.txt").write_text("A\n", encoding="utf-8")
        (sync_local / "nested" / "file_b.txt").write_text("B\n", encoding="utf-8")

        port = random.randint(20000, 40000)
        server_log = tmp_path / "server.log"
        server_cmd = [str(server_bin), "--port", str(port), "--root", str(server_root), "--log", str(server_log)]
        server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_for_port(port)

            # First client run: register user and exercise commands
            client_log = client_work / "client.log"
            endpoint = f"alice@127.0.0.1:{port}"
            command_sequence = textwrap.dedent(
                """
                pass123
                y
                pass123
                LIST
                MKDIR dir1
                UPLOAD foo.txt dir1/foo.txt
                LIST dir1
                DOWNLOAD dir1/foo.txt downloaded.txt
                MOVE dir1/foo.txt dir1/foo2.txt
                COPY dir1/foo2.txt dir1/foo3.txt
                DELETE dir1/foo3.txt
                SYNC sync_local dir_sync
                RMDIR dir1
                EXIT
                """
            ).lstrip()
            result = run_client(
                client_bin,
                endpoint,
                ["--log", str(client_log), "--max-upload-rate", "131072", "--max-download-rate", "131072"],
                command_sequence,
                client_work,
            )

            assert result.returncode == 0, f"Client exited with {result.returncode}: {result.stderr}\n{result.stdout}"
            stdout_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if not any("Logged as alice" in line for line in stdout_lines):
                raise AssertionError(f"Authentication failed. Output: {stdout_lines}")
            ok_count = sum(1 for line in stdout_lines if "OK" in line)
            assert ok_count >= 6, f"Expected multiple OK responses, got {ok_count}: {stdout_lines}"
            bar_file = client_work / "downloaded.txt"
            assert bar_file.exists(), "Downloaded file missing"
            assert bar_file.read_text(encoding="utf-8") == "hello from minidrive\n"

            user_root = server_root / "users" / "alice"
            assert user_root.exists(), f"User root missing at {user_root}"
            remote_sync = user_root / "dir_sync"
            assert remote_sync.exists(), "Remote sync directory missing"
            ensure_same_tree(sync_local, remote_sync)
            assert not (user_root / "dir1").exists(), "dir1 should have been removed"

            # Second run: verify login without registration
            result_login = run_client(
                client_bin,
                endpoint,
                ["--log", str(client_log)],
                "pass123\nEXIT\n",
                client_work,
            )
            assert result_login.returncode == 0, result_login.stderr
            assert any("Logged as alice" in line for line in result_login.stdout.splitlines())

            # Public mode warning check
            result_public = run_client(
                client_bin,
                "127.0.0.1:" + str(port),
                [],
                "EXIT\n",
                client_work,
            )
            assert "[warning] operating in public mode" in result_public.stdout

        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
