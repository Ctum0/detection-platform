# pipelines/

Sigma processing pipelines (field mappings / transformations applied at
convert time). Referenced explicitly, e.g.:

```bash
sigma convert -t splunk -p platform/pipelines/linux_auth.yml detections/sigma/...
```

`linux_auth.yml` is a pass-through placeholder (priority 20,
`transformations: []`, which pySigma accepts as a valid no-op) — auth.log ships in a shape the rules consume directly.
Add real pipelines here if a backend ever needs field renames.
