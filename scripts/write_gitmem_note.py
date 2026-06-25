#!/usr/bin/env python3
"""
Small helper to insert a note directly into the local gitmem storage
when the MCP gitmem server is unavailable.

Usage:
  scripts/write_gitmem_note.py <project> <title>
  # content is read from STDIN (markdown with frontmatter)
"""

import datetime
import json
import pathlib
import sys
import uuid


def extract_tags(markdown: str) -> list[str]:
    """Very small front‑matter tag extractor (expects YAML style)."""
    if not markdown.startswith("---"):
        return []
    end = markdown.find("\n---", 3)
    if end == -1:
        return []
    fm = markdown[3:end]
    tags: list[str] = []
    in_tags = False
    for line in fm.splitlines():
        if line.strip().startswith("tags:"):
            in_tags = True
            continue
        if in_tags:
            if line.startswith("- "):
                tags.append(line[2:].strip())
            elif line.strip() == "" or not line.startswith(" "):
                break
    return tags


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: write_gitmem_note.py <project> <title>\n")
        sys.exit(1)

    project = sys.argv[1]
    title = sys.argv[2]
    content = sys.stdin.read()

    base = pathlib.Path("tmp/gitmem-notes-store")
    now = datetime.datetime.utcnow()
    mem_id = f"mem_{uuid.uuid4()}"
    rel_path = pathlib.Path("memories") / project / f"{now.year:04d}" / f"{now.month:02d}" / f"{now.day:02d}" / f"{mem_id}.json"
    abs_path = base / rel_path
    abs_path.parent.mkdir(parents=True, exist_ok=True)

    obj = {
        "id": mem_id,
        "version": 1,
        "type": "note",
        "title": title,
        "content": content,
        "tags": extract_tags(content),
        "source": None,
        "score": None,
        "ttl": None,
        "created_at": now.isoformat() + "Z",
        "updated_at": now.isoformat() + "Z",
        "deleted_at": None,
        "encryption": {"algo": None, "kid": None, "encrypted": False},
        "compat": None,
    }
    abs_path.write_text(json.dumps(obj, indent=2))

    manifest_path = base / "meta" / project / "MANIFEST.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    else:
        manifest = {"ids": {}, "recent": []}

    manifest["ids"][mem_id] = str(rel_path)
    manifest["recent"] = [mem_id] + [m for m in manifest.get("recent", []) if m != mem_id]
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"wrote {mem_id} to {abs_path}")


if __name__ == "__main__":
    main()
