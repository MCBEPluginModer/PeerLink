# Scenario tests

Basic automated scenario entry points for the messenger.

## Run

```bash
python tests/scenario_runner.py --binary messenger.exe --cwd . --scenario smoke-two-peers
```

Current automated coverage is intentionally small and safe:
- process startup
- peer connection bootstrap
- basic command execution

Extend the runner with invite/private/group/file scenarios as the protocol stabilizes.
