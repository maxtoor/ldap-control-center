#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen


IMAGE_LINE_RE = re.compile(r"^(\s*image:\s*)([a-zA-Z0-9._/-]+):([a-zA-Z0-9._-]+)(\s*)$")
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


@dataclass
class ImageRef:
    repository: str
    current_tag: str
    latest_tag: str


def run(cmd: List[str], cwd: Path, dry_run: bool = False, capture_output: bool = False) -> subprocess.CompletedProcess:
    pretty = " ".join(cmd)
    if dry_run:
        print(f"[dry-run] {pretty}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    print(f"[run] {pretty}")
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=True,
        text=True,
        capture_output=capture_output,
    )


def run_redirect(cmd: List[str], output_path: Path, cwd: Path, dry_run: bool = False) -> None:
    pretty = " ".join(cmd)
    if dry_run:
        print(f"[dry-run] {pretty} > {output_path}")
        return
    print(f"[run] {pretty} > {output_path}")
    with output_path.open("w", encoding="utf-8") as out:
        subprocess.run(cmd, cwd=str(cwd), check=True, text=True, stdout=out)


def semver_tuple(tag: str) -> Optional[Tuple[int, int, int]]:
    match = SEMVER_RE.match(tag)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def fetch_hub_tags(repository: str, page_size: int = 100) -> List[str]:
    tags: List[str] = []
    next_url = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size={page_size}"
    while next_url:
        req = Request(next_url, headers={"Accept": "application/json", "User-Agent": "gestan-autoupdate/1.0"})
        with urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        for result in payload.get("results", []):
            name = (result.get("name") or "").strip()
            if name:
                tags.append(name)
        next_url = payload.get("next")
    return tags


def latest_semver_tag(tags: List[str]) -> Optional[str]:
    semvers: List[Tuple[Tuple[int, int, int], str]] = []
    for tag in tags:
        sv = semver_tuple(tag)
        if sv is not None:
            semvers.append((sv, tag))
    if not semvers:
        return None
    semvers.sort(key=lambda item: item[0], reverse=True)
    return semvers[0][1]


def parse_images(compose_text: str) -> Dict[str, str]:
    images: Dict[str, str] = {}
    for line in compose_text.splitlines():
        match = IMAGE_LINE_RE.match(line)
        if not match:
            continue
        repo = match.group(2)
        tag = match.group(3)
        images[repo] = tag
    return images


def find_updates(images: Dict[str, str]) -> List[ImageRef]:
    updates: List[ImageRef] = []
    for repo, current_tag in images.items():
        current_sv = semver_tuple(current_tag)
        if current_sv is None:
            continue
        try:
            tags = fetch_hub_tags(repo)
        except Exception as exc:
            print(f"[warn] impossibile interrogare Docker Hub per {repo}: {exc}")
            continue
        latest = latest_semver_tag(tags)
        if not latest:
            continue
        latest_sv = semver_tuple(latest)
        if latest_sv and latest_sv > current_sv:
            updates.append(ImageRef(repository=repo, current_tag=current_tag, latest_tag=latest))
    return updates


def apply_updates_to_compose(compose_text: str, updates: List[ImageRef]) -> str:
    mapping = {u.repository: (u.current_tag, u.latest_tag) for u in updates}
    new_lines: List[str] = []
    for line in compose_text.splitlines():
        match = IMAGE_LINE_RE.match(line)
        if not match:
            new_lines.append(line)
            continue
        prefix, repo, current_tag, suffix = match.groups()
        if repo in mapping and current_tag == mapping[repo][0]:
            new_lines.append(f"{prefix}{repo}:{mapping[repo][1]}{suffix}")
        else:
            new_lines.append(line)
    return "\n".join(new_lines) + "\n"


def smoke_test(project_root: Path, dry_run: bool = False) -> None:
    script = (
        "python - <<'PY'\n"
        "import urllib.request\n"
        "from app.ldap_client import LDAPClient\n"
        "for url in ('http://127.0.0.1:8000/login','http://127.0.0.1:8000/password/forgot'):\n"
        "    with urllib.request.urlopen(url, timeout=10) as r:\n"
        "        print(url, r.status)\n"
        "client = LDAPClient()\n"
        "print('users', len(client.list_users()))\n"
        "print('groups', len(client.list_groups()))\n"
        "PY"
    )
    run(["docker", "compose", "exec", "-T", "app", "sh", "-lc", script], cwd=project_root, dry_run=dry_run)


def rollback(project_root: Path, compose_backup_path: Path, compose_path: Path, dry_run: bool = False) -> None:
    print("== ROLLBACK ==")
    if dry_run:
        print(f"[dry-run] restore {compose_backup_path} -> {compose_path}")
    else:
        shutil.copy2(compose_backup_path, compose_path)
    run(["docker", "compose", "up", "-d", "--force-recreate", "openldap", "phpldapadmin", "app"], cwd=project_root, dry_run=dry_run)
    run(["docker", "compose", "ps"], cwd=project_root, dry_run=dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggiornamento automatico stack con backup e rollback")
    parser.add_argument("--project-root", default=".", help="Root progetto (default: .)")
    parser.add_argument("--compose-file", default="docker-compose.yml", help="Compose file (default: docker-compose.yml)")
    parser.add_argument("--skip-backup", action="store_true", help="Salta backup LDAP/compose")
    parser.add_argument("--dry-run", action="store_true", help="Non esegue comandi, mostra solo il piano")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    compose_path = (project_root / args.compose_file).resolve()
    if not compose_path.exists():
        print(f"Compose file non trovato: {compose_path}", file=sys.stderr)
        return 2

    compose_text = compose_path.read_text(encoding="utf-8")
    images = parse_images(compose_text)
    if not images:
        print("Nessuna immagine trovata nel compose.")
        return 0

    print("== Verifica aggiornamenti immagini ==")
    updates = find_updates(images)
    if not updates:
        print("Nessun aggiornamento disponibile.")
        return 0

    for upd in updates:
        print(f"- {upd.repository}: {upd.current_tag} -> {upd.latest_tag}")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = project_root / "backups" / f"autoupdate-{timestamp}"
    compose_backup_path = backup_dir / "docker-compose.yml.bak"

    try:
        print("== Backup ==")
        if not args.skip_backup:
            if args.dry_run:
                print(f"[dry-run] mkdir -p {backup_dir}")
            else:
                backup_dir.mkdir(parents=True, exist_ok=True)

            if args.dry_run:
                print(f"[dry-run] cp {compose_path} {compose_backup_path}")
            else:
                shutil.copy2(compose_path, compose_backup_path)

            run_redirect(
                ["docker", "compose", "exec", "-T", "openldap", "sh", "-lc", "slapcat -n 1"],
                backup_dir / "ldap-data.ldif",
                cwd=project_root,
                dry_run=args.dry_run,
            )
            run_redirect(
                ["docker", "compose", "exec", "-T", "openldap", "sh", "-lc", "slapcat -n 0"],
                backup_dir / "ldap-config.ldif",
                cwd=project_root,
                dry_run=args.dry_run,
            )
            print(f"Backup salvato in: {backup_dir}")
        else:
            print("Backup saltato (--skip-backup).")
            if not args.dry_run:
                backup_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(compose_path, compose_backup_path)

        print("== Aggiornamento docker-compose.yml ==")
        updated_compose = apply_updates_to_compose(compose_text, updates)
        if args.dry_run:
            print("[dry-run] update tags nel compose")
        else:
            compose_path.write_text(updated_compose, encoding="utf-8")

        print("== Deploy aggiornamento ==")
        run(["docker", "compose", "pull"], cwd=project_root, dry_run=args.dry_run)
        run(["docker", "compose", "up", "-d", "--force-recreate", "openldap"], cwd=project_root, dry_run=args.dry_run)
        run(["docker", "compose", "up", "-d", "--force-recreate", "phpldapadmin"], cwd=project_root, dry_run=args.dry_run)
        run(["docker", "compose", "up", "-d", "--force-recreate", "app"], cwd=project_root, dry_run=args.dry_run)

        print("== Smoke test ==")
        smoke_test(project_root=project_root, dry_run=args.dry_run)
        run(["docker", "compose", "ps"], cwd=project_root, dry_run=args.dry_run)
        print("Aggiornamento completato con successo.")
        return 0
    except Exception as exc:
        print(f"Errore durante aggiornamento: {exc}", file=sys.stderr)
        rollback(project_root=project_root, compose_backup_path=compose_backup_path, compose_path=compose_path, dry_run=args.dry_run)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
