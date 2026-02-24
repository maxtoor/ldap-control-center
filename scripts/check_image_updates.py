#!/usr/bin/env python3
import argparse
import json
import os
import re
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import Request, urlopen


SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
IMAGE_RE = re.compile(r"^\s*image:\s*([a-zA-Z0-9._/-]+):([a-zA-Z0-9._-]+)\s*$")


@dataclass
class ImageTag:
    repository: str
    current_tag: str
    latest_tag: Optional[str]


def parse_compose_images(compose_path: Path) -> Dict[str, str]:
    images: Dict[str, str] = {}
    for line in compose_path.read_text(encoding="utf-8").splitlines():
        match = IMAGE_RE.match(line)
        if not match:
            continue
        repo = match.group(1)
        tag = match.group(2)
        images[repo] = tag
    return images


def semver_tuple(tag: str) -> Optional[Tuple[int, int, int]]:
    match = SEMVER_RE.match(tag)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def fetch_hub_tags(repository: str, page_size: int = 100) -> List[str]:
    tags: List[str] = []
    next_url = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size={page_size}"

    while next_url:
        req = Request(next_url, headers={"Accept": "application/json", "User-Agent": "gestan-update-check/1.0"})
        with urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        for result in payload.get("results", []):
            name = (result.get("name") or "").strip()
            if name:
                tags.append(name)
        next_url = payload.get("next")
    return tags


def latest_semver(tags: List[str]) -> Optional[str]:
    semvers = []
    for tag in tags:
        sv = semver_tuple(tag)
        if sv is not None:
            semvers.append((sv, tag))
    if not semvers:
        return None
    semvers.sort(key=lambda item: item[0], reverse=True)
    return semvers[0][1]


def check_updates(compose_path: Path) -> List[ImageTag]:
    images = parse_compose_images(compose_path)
    report: List[ImageTag] = []

    for repo, current_tag in images.items():
        current_sv = semver_tuple(current_tag)
        if current_sv is None:
            report.append(ImageTag(repository=repo, current_tag=current_tag, latest_tag=None))
            continue

        try:
            tags = fetch_hub_tags(repo)
        except Exception:
            report.append(ImageTag(repository=repo, current_tag=current_tag, latest_tag=None))
            continue

        latest = latest_semver(tags)
        report.append(ImageTag(repository=repo, current_tag=current_tag, latest_tag=latest))
    return report


def format_report(items: List[ImageTag]) -> str:
    lines: List[str] = []
    lines.append("Verifica aggiornamenti immagini Docker")
    lines.append("")
    for item in items:
        if item.latest_tag is None:
            lines.append(f"- {item.repository}:{item.current_tag} -> impossibile determinare latest semver")
            continue
        current_sv = semver_tuple(item.current_tag)
        latest_sv = semver_tuple(item.latest_tag)
        if current_sv is not None and latest_sv is not None and latest_sv > current_sv:
            lines.append(f"- {item.repository}:{item.current_tag} -> disponibile {item.latest_tag}")
        else:
            lines.append(f"- {item.repository}:{item.current_tag} -> aggiornato")
    return "\n".join(lines)


def smtp_enabled() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip() and os.getenv("SMTP_FROM_EMAIL", "").strip())


def send_email(subject: str, body: str, recipient: str) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    port = int(os.getenv("SMTP_PORT", "587"))
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
    use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes", "on"}
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    from_email = os.getenv("SMTP_FROM_EMAIL", "").strip()
    from_name = os.getenv("SMTP_FROM_NAME", "LDAP Control Center").strip() or "LDAP Control Center"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient
    msg.set_content(body)

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with smtp_class(host, port, timeout=20) as server:
        if use_tls and not use_ssl:
            server.starttls()
        if username:
            server.login(username, password)
        server.send_message(msg)


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlla aggiornamenti immagini in docker-compose.yml")
    parser.add_argument(
        "--compose-file",
        default="docker-compose.yml",
        help="Percorso docker-compose.yml (default: docker-compose.yml)",
    )
    parser.add_argument(
        "--email-to",
        default=os.getenv("UPDATE_NOTIFY_EMAIL", "").strip(),
        help="Destinatario notifica email (default: env UPDATE_NOTIFY_EMAIL)",
    )
    args = parser.parse_args()

    compose_path = Path(args.compose_file)
    if not compose_path.exists():
        raise FileNotFoundError(f"File non trovato: {compose_path}")

    items = check_updates(compose_path)
    report = format_report(items)
    print(report)

    has_updates = False
    for item in items:
        if item.latest_tag is None:
            continue
        current_sv = semver_tuple(item.current_tag)
        latest_sv = semver_tuple(item.latest_tag)
        if current_sv is not None and latest_sv is not None and latest_sv > current_sv:
            has_updates = True
            break

    if has_updates and args.email_to:
        if not smtp_enabled():
            print("ATTENZIONE: update trovato ma SMTP non configurato, email non inviata.")
            return 1
        send_email(
            subject="LDAP Control Center - Aggiornamenti immagini disponibili",
            body=report,
            recipient=args.email_to,
        )
        print(f"Notifica inviata a: {args.email_to}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
