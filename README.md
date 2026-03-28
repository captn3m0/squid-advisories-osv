# Squid Security Advisories (OSV Format)

Security advisories for [Squid](https://www.squid-cache.org/) re-published in the [OSV format](https://ossf.github.io/osv-schema/).

## Coverage

- **2020–present**: sourced from the [GitHub Security Advisories](https://github.com/squid-cache/squid/security/advisories) for `squid-cache/squid`
- **2002–2020**: sourced from [squid-cache.org/Advisories/](https://www.squid-cache.org/Advisories/)

Advisory IDs follow the Squid project's own numbering: `SQUID-YYYYgsN` (e.g. `SQUID-2023-1`).

## File naming

```
advisories/SQUID-YYYY-N.json
```

## Regenerating

```bash
uv run python main.py
```

Requires the [GitHub CLI](https://cli.github.com/) (`gh`) to be authenticated.

## Schema

Files conform to [OSV schema 1.6.0](https://ossf.github.io/osv-schema/).
Key fields:

| Field | Content |
|---|---|
| `id` | `SQUID-YYYY-N` |
| `aliases` | GHSA ID and/or CVE ID(s) |
| `summary` | Short vulnerability title |
| `details` | Full advisory text (GitHub-sourced entries only) |
| `affected` | Squid version ranges from the advisory |
| `references` | Links to GitHub advisory, CVE, and squid-cache.org |

## License

Code: MIT. Advisory content copyright belongs to the Squid project.
