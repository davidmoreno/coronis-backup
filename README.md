# Coronis Backup

Simple backups.

## features

- Email notification on success and error - One email per day and peace of mind it did it
- Uses SSH for remote access (uses remote tar, and custom commands as pg_dump)
- Encrypted at rest with GPG (optional)
- Multiple server backups in one file
- In real use since 2018

## Example use:

Normally just add this commands to cron as desired, optionally with `chronic` from `moreutils`.

### Full backup

```sh
backup.py --plan example/plan.yaml /mnt/backups/full/
```

### incremental (last 24h)

```sh
backup.py -i --plan example/plan.yaml /mnt/backups/partial/
```
