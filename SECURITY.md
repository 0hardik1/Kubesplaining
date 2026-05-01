# Security Policy

## Supported versions

Security fixes are backported to the latest minor release line on `main`.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

**Please use [GitHub Private Vulnerability Reporting](https://github.com/0hardik1/kubesplaining/security/advisories/new) — it is the only supported channel.**

Open the link above, or in the repo navigate to the **Security** tab → **Advisories** → **Report a vulnerability**. The report stays private to the maintainers, sits inside GitHub's audit log, and lets us coordinate a CVE before public disclosure if one is warranted.

**Please do not file public GitHub issues, pull requests, or Discussions for security vulnerabilities.** Public disclosure before a fix is shipped puts users at risk; route everything through the form above.

### What to include

- The affected version (output of `kubesplaining version`).
- The smallest reproducer you can construct — a snapshot fragment, a CLI invocation, or a fixture manifest.
- The impact you observed (incorrect finding, missing finding, crash, information disclosure, etc.) and the impact you believe is achievable.
- Any suggested fix or mitigation.

### What happens next

- **Acknowledgment** within 5 business days that the report has been received.
- **Initial assessment** within 14 business days — confirming whether the issue is a vulnerability, requesting any missing information, and proposing a target fix window.
- **Coordinated disclosure** within 90 days of acknowledgment, sooner if a fix lands first. Reporters who would like credit in the release notes / advisory will be acknowledged unless they ask otherwise.

### Out of scope

- Findings produced by Kubesplaining about your own cluster — those are working-as-intended diagnostic output, not vulnerabilities in Kubesplaining. File an issue if you believe a finding is wrong (false positive / false negative).
- Vulnerabilities in third-party dependencies that have already been disclosed upstream — please report those to the upstream project. Dependabot keeps our dependency tree current; if a CVE-tagged dep needs a Kubesplaining-side bump, a regular issue or PR is fine.
- Issues that require an attacker who already has cluster-admin or local root on the machine running Kubesplaining.
