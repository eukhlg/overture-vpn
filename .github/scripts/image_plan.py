"""Resolve image inputs before building; only main events may publish testing."""
import hashlib
import json
import os
import re
import subprocess

REPOS = {"app": "eukhlg/overture-vpn", "l2tp": "eukhlg/l2tp-go", "ipsec": "eukhlg/ipsec-go"}


def feature_tag(name):
    if not name or "\n" in name or "\r" in name:
        raise ValueError("A feature name is required")
    slug = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip(".-") or "feature"
    if slug != name or len(slug) > 100:
        slug = slug[:90] + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]
    return "testing-" + slug


def resolve(repo, ref):
    # Explicit branches or tags, never an ambiguous short ref or shell command.
    if not ref.startswith(("refs/heads/", "refs/tags/")):
        ref = "refs/heads/" + ref
    subprocess.run(["git", "check-ref-format", ref], check=True, capture_output=True)
    result = subprocess.run(
        ["git", "ls-remote", "https://github.com/" + repo + ".git", ref, ref + "^{}"],
        check=True, capture_output=True, text=True,
    )
    refs = dict(line.split("\t", 1)[::-1] for line in result.stdout.splitlines())
    sha = refs.get(ref + "^{}", refs.get(ref, ""))
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"Cannot resolve {repo} {ref}")
    return sha


def plan(event_name, event, resolve_ref=resolve):
    if event_name == "release":
        tag = event["release"]["tag_name"]
        if not re.fullmatch(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
            raise ValueError("A numeric stable release version is required")
        return {"tag": tag.removeprefix("v"), "app_sha": resolve_ref(REPOS["app"], "refs/tags/" + tag), "l2tp_sha": "", "ipsec_sha": ""}
    refs = dict.fromkeys(REPOS, "main")
    exact = {}
    if event_name == "workflow_dispatch":
        inputs = event["inputs"]
        tag = feature_tag(inputs["feature"])
        refs = {key: inputs.get(key + "_ref") or "main" for key in REPOS}
    else:
        if event_name == "push":
            if not event["ref"].startswith("refs/heads/") or event.get("deleted"):
                raise ValueError("Only branch pushes build testing images")
            branch = event["ref"].removeprefix("refs/heads/")
            source = "app"
            sha = event["after"]
        elif event_name == "repository_dispatch":
            payload = event["client_payload"]
            source = next((key for key in ("l2tp", "ipsec") if REPOS[key] == payload["repository"]), None)
            if source is None:
                raise ValueError("Unexpected module repository")
            branch, sha = payload["branch"], payload["sha"]
            if not branch or "\n" in branch or "\r" in branch:
                raise ValueError("Invalid source branch")
        else:
            raise ValueError("Unexpected image event")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Invalid source commit")
        tag = "testing" if branch == "main" else feature_tag(branch)
        if branch != "main":
            exact[source] = sha
    result = {"tag": tag}
    for key, repo in REPOS.items():
        result[key + "_sha"] = exact[key] if key in exact else resolve_ref(repo, refs[key])
    return result


if __name__ == "__main__":
    with open(os.environ["GITHUB_EVENT_PATH"]) as stream:
        selected = plan(os.environ["GITHUB_EVENT_NAME"], json.load(stream))
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        for key, value in selected.items():
            print(f"{key}={value}", file=stream)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
        print("Image selection: ```" + json.dumps(selected, sort_keys=True) + "```", file=stream)
