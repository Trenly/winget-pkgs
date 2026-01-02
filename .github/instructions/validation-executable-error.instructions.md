---
applyTo: "manifests/**/*"
---

# Copilot instructions: Validation-Executable-Error

Mandatory requirement
- These instructions are MANDATORY when a pull request is labeled `Validation-Executable-Error`.
- Any automated agent, Copilot instance, or human-in-the-loop reviewer receiving a PR with this label MUST run the steps in this file and MUST NOT skip them. Failure to execute these instructions constitutes an incomplete validation for the PR.

Purpose
- When a pull request is labeled `Validation-Executable-Error`, a Copilot agent should evaluate the changed manifest files and determine whether any installer in the manifest is a portable installer. If so, the agent shall search for documentation about the submitted application and determine whether the application supports a version argument or a help argument. If no portable installers are present, the agent should do nothing.

Scope & assumptions
- This instruction is intended for an automated Copilot agent that can read repository files changed in a PR and perform read-only web lookups and text searches.
- Do NOT execute or run any untrusted binaries or installers. Only inspect documentation, official websites, repositories, release notes, README files, and other public documentation.
- A manifest may contain multiple installers. If ANY installer entry has `InstallerType: portable` or `NestedInstallerType: portable`, the agent must perform the portable checks for that manifest.
- The agent should only evaluate manifest files that are added or modified in the pull request.
- The agent should NEVER attempt to search or recursively evaluate the `/manifests/` directory outside of the changed files in the PR.

Step-by-step behaviour for the agent
1. Locate changed manifest files in the pull request
   - Use the PR changed file list to identify files under the `manifests/` directory that were added or modified by the PR.
   - Only evaluate manifest files included in the PR.

2. For each changed manifest file:
   a. Parse the manifest YAML/JSON to extract installer entries and the following fields when present:
      - `InstallerType`
      - `NestedInstallerType`
      - Any array of `Installers` or entries that specify installer metadata.
   b. Determine whether ANY installer entry has `InstallerType: portable` or `NestedInstallerType: portable`.
      - Treat comparison as case-insensitive.
      - If none are `portable`, skip this manifest and record that no portable installer was found (no further action).

3. If a manifest contains at least one portable installer, perform documentation and usage option discovery:
   a. Identify the application/project name and common metadata from the manifest (package name, homepage, publisher, repository URLs if present).
   b. Search authoritative and likely sources for usage/CLI docs and references:
      - Official homepage or vendor website
      - Project repository (GitHub, GitLab, etc.) — README, docs/ directory, releases, tags
      - Project wiki or user manual
      - Packaged artifacts (if the manifest references a GitHub release or similar, check release notes or attached files descriptions)
      - Search engines if needed for authoritative pages (prefer official project pages)
   c. Look specifically for evidence that the application binary (or the portable distribution) accepts a version argument or a help argument. Search for common patterns and examples:
      - Flags/arguments to detect: `--version`, `-v`, `version`, `--help`, `-h`, `help` and any documented `--ver`, `/version` forms for Windows-native apps.
      - Examples of usage lines such as `appname --version`, `appname -v`, `appname --help`, `appname -h` in README or docs.
      - CLI documentation pages, man pages, usage examples, and command-line reference sections.
   d. If the project is GUI-only with no documented command-line options, note that no version/help arguments are documented.

4. Evidence collection and reporting
   - For each manifest evaluated (that had a portable installer), produce a small report with the following fields:
     - **Manifest path**: path to the evaluated manifest file in the PR (e.g., `manifests/a/Example/1.2.3/manifest.yaml`).
     - **Installers examined**: list of installer entries and their `InstallerType` / `NestedInstallerType` values.
     - **Portable detected**: `yes` or `no` (should be `yes` for manifests that triggered the search).
     - **Version flag evidence**: `found` or `not found`; if found, provide the exact snippet or quoted text and a URL to the source (README, docs, release notes). If multiple variants exist, list them (e.g., `--version`, `-v`).
     - **Help flag evidence**: `found` or `not found`; include snippet and URL if found.
     - **Notes**: any caveats such as GUI-only application, ambiguous docs, or need for human follow-up.
     - **Confidence**: low/medium/high depending on clarity of evidence (e.g., direct CLI examples in README -> high).

5. Output format
    - The agent must post its results as a GitHub comment on the pull request. The comment body MUST contain a YAML code block (fenced with triple backticks and the `yaml` language tag) with a single YAML document describing the findings.
    - The YAML document SHOULD list evaluated manifests and findings using the template below. Use explicit fields (no free-form prose) so downstream automation or human reviewers can parse the result easily. Include verbatim snippets and source URLs where evidence is found.
    - If no changed manifests contain portable installers, the agent should still post a short YAML document inside the YAML code block with `no_portable_manifests: true` and a `message` field explaining that no portable installers were detected.

YAML template (example)
```yaml
manifests:
   - path: "manifests/a/Example/1.2.3/manifest.yaml"
      portable_detected: true
      version_flag_evidence:
         found: true
         variants: ["--version", "-v"]
         snippets:
            - text: "ExampleApp --version"
               url: "https://github.com/example/example#readme"
      help_flag_evidence:
         found: false
         snippets: []
      notes: "CLI options documented in README"
      confidence: "high"
no_portable_manifests: false
```

Notes about the template
- Use the manifest path exactly as it appears in the repository.
- `snippets` entries must include both `text` (a short verbatim snippet, 1-3 lines) and `url` (direct link to the source of the snippet).
- `confidence` values: `low`, `medium`, `high`.
- If there are multiple manifests with portable installers, include each as an item under `manifests`.

Behavioral rules and constraints
- Do not attempt to download, extract, or execute any executables, archives, or installers from release assets.
- Prefer official project documentation and repository sources over third-party blog posts. If only third-party sources exist, include them but mark confidence as lower.
- Be explicit about where evidence was found: copy small verbatim snippets (one or two lines) with a direct URL.
- Treat multiple installers in a manifest independently but report them collectively for the manifest.

Examples
- If `manifests/a/Foo/1.0.0/manifest.yaml` contains two installers, one with `InstallerType: exe` and the other with `NestedInstallerType: portable`, the agent must perform the documentation search and report results for `Foo/1.0.0`.
- If `manifests/b/Bar/2.3.4/manifest.yaml` has only `InstallerType: exe` and `NestedInstallerType` omitted, the agent should skip `Bar` and report no action for that manifest.

Human follow-up suggestions
- If the agent cannot find any documentation about CLI options but a portable binary is included in release assets, suggest a human reviewer to inspect the portable package manually in a safe environment.

Revision history
- Created: 2026-01-02 — initial instructions for Validation-Executable-Error Copilot behaviour.
