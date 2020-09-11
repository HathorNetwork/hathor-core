## Daemonizing with Supervisor

Create a `run_hathord` with execution permission:

```
#!/bin/bash
exec pipenv run hathor-cli run_node --hostname <YOUR_HOSTNAME_OR_PUBLIC_IP_ADDRESS> --listen tcp:40403 --status 8001 --testnet --peer peer_id.json
```

There follows a configuration template to Supervisor:

```
[program:hathord]
command=/path/to/hathor-python/run_hathord
user=ubuntu
directory=/path/to/hathor-python/
stdout_logfile=/path/to/logs/hathord.log
stderr_logfile=/path/to/logs/hathord.err
```

Recommended aliases to control `hathord`:

```
alias stop-hathord='sudo supervisorctl stop hathord'
alias start-hathord='sudo supervisorctl start hathord'
alias status-hathord='sudo supervisorctl status hathord'
alias restart-hathord='sudo supervisorctl restart hathord'
alias p2p-hathord='curl http://localhost:8001/'
```
