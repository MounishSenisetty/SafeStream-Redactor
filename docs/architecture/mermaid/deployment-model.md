# Deployment Model

The system is packaged once and installed as either a PyPI package or a
container image on a local-first, self-contained target host that reads input
and writes redacted output plus a report to the local file system.

> Validated against `pyproject.toml` (wheel/sdist + `safestream` entry point),
> `Dockerfile`, and `.github/workflows/` (`ci.yml`, `docker.yml`,
> `publish.yml`).

```mermaid
flowchart TB
    subgraph Build["Build environment"]
        Source["Source"]
        BuildPkg["Build & packaging"]
        Source --> BuildPkg
    end
    subgraph Registry["Registry"]
        Artifact["Package (PyPI) / container image (GHCR)"]
    end
    subgraph Host["Target host<br/>(local-first, self-contained)"]
        Instance["Installed package<br/>or container instance"]
        FS[("Local file system<br/>input + redacted output + report")]
        Instance -->|"reads / writes"| FS
    end

    BuildPkg --> Registry
    Artifact --> Instance
```
