#!/usr/bin/env python3
"""
AGPLv3

Copyright (C) 2020-2025  Coralbits

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

https://github.com/davidmoreno/coronis-backup
"""


import argparse
import datetime
import json
import logging
import os
import smtplib
import traceback
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pexpect
import sh
import yaml


# Custom logger class with multiple destinations
class ColoredHandlerAndKeep(logging.Handler):
    # ANSI colors for console output
    LEVEL_TO_COLOR = {
        0: "\033[0;36m",  # DEBUG - Cyan
        10: "\033[0;34m",  # INFO - Blue
        20: "\033[1;m",  # WARNING - Bold
        30: "\033[0;33m",  # ERROR - Yellow
        40: "\033[0;31m",  # CRITICAL - Red
        50: "\033[1;31m",  # FATAL - Bold Red
    }
    RESET = "\033[1;m"
    FORMAT = "{levelname:5} -- {datetime} -- {color}{message}{reset}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keep = []

    def handle(self, record):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = ColoredHandlerAndKeep.LEVEL_TO_COLOR[record.levelno]
        try:
            message = record.msg % record.args
        except Exception:
            message = record.msg
        self.keep.append([now, record.levelno, message])
        print(
            ColoredHandlerAndKeep.FORMAT.format(
                color=color,
                reset=ColoredHandlerAndKeep.RESET,
                datetime=now,
                message=message,
                levelname=record.levelname,
            )
        )


# HTML colors for email output
LOG_COLORS = {
    # Using a color palette with good contrast ratios
    10: "#3AAFA9",  # DEBUG - Teal
    20: "#6B5B95",  # INFO - Purple
    30: "#F39C12",  # WARNING - Orange
    40: "#E74C3C",  # ERROR - Red
    50: "#C0392B",  # CRITICAL - Dark Red
}

# Email styling constants
EMAIL_STYLES = {
    "container": "font-family: Sans Serif;",
    "header": "padding-bottom: 20px;",
    "table": "border-collapse: collapse; border: 1px solid #2185d0;",
    "table_header": "background: #2185d0; color: white;",
    "table_cell": "border: 1px solid #2185d0; padding: 5px;",
    "success_cell": "background: #21ba45;",
    "warning_cell": "background: #f2784b;",
    "error_cell": "background: #db2828;",
    "logs_container": "margin-top: 20px;",
    "logs_header": "color: #2185d0;",
    "logs_box": "background: #f8f9fa; padding: 15px; border-radius: 5px;",
    "logs_text": "margin: 0; font-family: monospace;",
}

log_handler = ColoredHandlerAndKeep()
logger = logging.getLogger("backup-borg")
logger.addHandler(log_handler)
logger.setLevel(logging.DEBUG)  # Ensure we capture all log levels

SSH_ARGS = [
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
]


class BackupResult:
    OK = "OK"
    WARN = "WARN"
    NOK = "NOK"

    value = OK

    def update(self, result: str):
        """
        Only updates to worse results.
        """
        if str(result).startswith("WARN"):
            if self.value == "OK":
                self.value = self.WARN
        if str(result).startswith("NOK"):
            self.value = self.NOK

    def __str__(self):
        return self.value


class Backup:
    options: dict
    plan: dict
    tobackup: list
    servers: list[str, dict]
    path: str
    mailto: list
    stats: dict
    smtp: dict
    start_time: datetime.datetime

    def __init__(self):
        self.start_time = datetime.datetime.now()
        self.stats = {}
        self.mailto = []
        self.parse_args()
        self.parse_yaml()
        logger.debug("options: %s", self.options)
        logger.debug("servers: %s", self.servers)

    def parse_args(self):
        args = argparse.ArgumentParser(description="Backup script using borg backup")
        args.add_argument("yamlfile", help="YAML file with backup configuration")
        args.add_argument(
            "servernames", nargs="*", help="YAML file with backup configuration"
        )
        args.add_argument("--verbose", action="store_true", help="Verbose output")
        args.add_argument(
            "--test-email", action="store_true", help="Send test email with no data"
        )
        args.add_argument(
            "--no-email", action="store_true", help="Disable email sending"
        )

        self.options = args.parse_args()

    def parse_yaml(self):
        with open(self.options.yamlfile) as fd:
            data = yaml.safe_load(fd)

        self.servers = dict_drop(data, "default", "smtp")

        if self.options.servernames:
            try:
                self.servers = {
                    name: self.servers[name] for name in self.options.servernames
                }
            except KeyError as e:
                logger.error("Server %s not found in configuration", e)
                exit(1)
        self.path = data["default"]["path"]
        self.mailto = data["default"]["mailto"]
        self.smtp = data["smtp"]

    def run(self):
        if self.options.test_email:
            if not self.options.no_email:
                self.send_stats_email()
            return

        logger.info(f"Running backup with %s at %s", self.options.yamlfile, self.path)
        self.stats = {}
        for server in self.servers:
            self.backup(server)
        if not self.options.no_email:
            self.send_stats_email()
        else:
            self.send_stats_email(send_email=False)

    def backup(self, server: str):
        self.stats[server] = BackupServer(
            name=server,
            config=self.servers[server],
            path=self.path,
            options=self.options,
        ).run()

    def send_stats_email(self, *, send_email: bool = None):
        if send_email is None:
            send_email = not self.options.no_email
        email_stats(
            mailto=self.mailto,
            backupname=self.options.yamlfile,
            stats=self.stats,
            smtp=self.smtp,
            total_time=datetime.datetime.now() - self.start_time,
            send_email=send_email,
        )


class BackupServer:
    socat = None
    remote = None
    remote_unix_socket = None
    local_unix_socket = None
    stats: dict

    def __init__(self, *, name: str, config: dict, options: dict, path: str):
        self.logger = logger.getChild(name)
        self.name = name
        self.config = config
        self.path = path
        self.options = options
        self.remote_unix_socket = f"/tmp/{self.name}-{uuid.uuid4()}.sock"
        self.local_unix_socket = f"{self.path}/{self.name}.sock"
        self.tmpdir = "/tmp/coralbackups/"
        self.stats = {}

    def run(self):
        self.logger.info(
            f"Running backup for: %s with config: %s", self.name, self.config
        )
        try:
            self.prepare_stats()

            self.ensure_repository()
            self.prepare_socat()
            self.connect_to_host()
            self.setup_remote_borg_envvars()

            try:
                self.backup_paths()
            except Exception as e:
                self.logger.error("Error in backup paths: %s", e)
            try:
                self.backup_stdouts()
            except Exception as e:
                self.logger.error("Error in backup stdouts: %s", e)
        except Exception as e:
            traceback.print_exc()
            self.logger.error("Error in backup: %s", e)
        finally:
            self.close()
        self.logger.info("Backup finished: %s", self.stats)
        return self.stats

    def prepare_stats(self):
        for path in self.config.get("paths", []):
            self.stats[path] = {
                "type": "path",
                "compressed_size": 0,
                "uncompressed_size": 0,
                "deduplicated_size": 0,
                "result": "NOK_DEF",
            }
        for key, value in self.config.get("stdout", {}).items():
            self.stats[key] = {
                "type": "stdout",
                "compressed_size": 0,
                "uncompressed_size": 0,
                "deduplicated_size": 0,
                "result": "NOK_DEF",
            }

    def prepare_socat(self):
        assert not self.socat, "Socat already prepared"
        if os.path.exists(self.local_unix_socket):
            os.unlink(self.local_unix_socket)
        # I need a system background process for socat that I will close at close
        # socat UNIX-LISTEN:/var/run/borg/coralbits.com.sock,fork EXEC:"borg serve --append-only --restrict-to-path /nfs/backups/borg/coralbits.com"
        socatcmd = [
            "socat",
            f"UNIX-LISTEN:{self.local_unix_socket},fork",
            f'EXEC:"borg serve --append-only --restrict-to-path {self.path}/{self.name}"',
        ]

        self.socat = pexpect.spawn(socatcmd[0], socatcmd[1:], encoding="utf-8")
        logger.info("Started local socat: %s", " ".join(socatcmd))

    def connect_to_host(self, with_unix_socket: bool = True):
        user = self.config["auth"]["user"]
        server = self.name
        sudo = []
        if "become" in self.config["auth"]:
            sudo = self.config["auth"]["become"].split(" ")

        if with_unix_socket:
            options = ["-R", f"{self.remote_unix_socket}:{self.local_unix_socket}"]
            self.logger.debug(
                "Remote unix socket: %s <-> %s",
                self.remote_unix_socket,
                self.local_unix_socket,
            )
        else:
            options = []

        cmd = [
            "ssh",
            *options,
            f"{user}@{server}",
            *SSH_ARGS,
            "--",
            *sudo,
            "sh",
            "-i",
        ]
        self.logger.debug("cmd: %s", " ".join(cmd))

        class Output:
            def write(self, data: str):
                ANSI_RED = "\033[91m"
                ANSI_RESET = "\033[0m"
                print(ANSI_RED + data + ANSI_RESET, end="")

            def flush(self):
                pass

        logfile = None
        if self.options.verbose:
            logfile = Output()

        remote = pexpect.spawn(cmd[0], cmd[1:], logfile=logfile, encoding="utf-8")

        remote.sendline("export PS1='::PEXPECT:: '\n")  # to have in under control

        remote.expect(
            "::PEXPECT:: ", timeout=10
        )  # the one from the echo.. and two more?
        remote.expect("::PEXPECT:: ", timeout=10)
        remote.expect("::PEXPECT:: ", timeout=10)

        if remote.exitstatus:
            self.logger.error("Could not connect to %s", server)
            return
        self.remote = remote

    def disconnect_from_host(self):
        self.remote.close()
        self.remote = None

    def remote_command(self, cmd, timeout=10) -> tuple[str, str]:
        self.logger.debug("Executing remote command: %s", cmd)
        self.remote.sendline(cmd)
        self.remote.expect("::PEXPECT:: ", timeout=timeout)
        stdout = self.remote.before
        self.remote.sendline("echo ERROR CODE $?")
        self.remote.expect(r"ERROR CODE (\d+)", timeout=10)
        exit_code = self.remote.match.group(1)
        if exit_code != "0":
            self.logger.error("Error in command: \n%s", stdout)
        self.remote.expect("::PEXPECT:: ", timeout=10)
        stdout = stdout[stdout.index("\n") + 1 :]

        return stdout, exit_code

    def setup_remote_borg_envvars(self):
        # ensure socket exists
        try:
            self.remote_command(f"test -e {self.remote_unix_socket}")
        except BackupException:
            self.logger.error("Socket not created!")
            raise

        self.remote_command(
            "export BORG_PASSPHRASE=$( cat ~/.config/coralbackups/password )"
        )
        self.remote_command(
            f"export BORG_RSH=\"sh -c 'exec socat STDIO UNIX-CONNECT:{self.remote_unix_socket}'\""
        )

    def backup_paths(self):
        # execute borg command
        for path in self.config["paths"]:
            try:
                stats = self.backup_path(path)
                self.stats[path] = stats
            except Exception as e:
                traceback.print_exc()
                self.logger.error("Error backing up %s", path)

    def backup_path(self, path: str, *, basename: str = None):
        self.logger.info("Backing up %s", path)
        if not basename:
            basename = path.replace("/", "-").strip("-")
        dt = datetime.datetime.now().strftime("%Y%m%d%H%M")

        backupname = f"{dt}-{basename}"

        try:
            info, exit_code = self.remote_command(
                f"borg create --json 'ssh://borg-server/{self.path}/{self.name}::{backupname}' '{path}'",
                timeout=24 * 60 * 60,
                # allow any exit code
            )
            try:
                # info may contain some other suff, we get from first { to last }, ignoring everything else, and multiline
                info = info[info.index("{") : info.rindex("}") + 1]

                stats = json.loads(info)["archive"]["stats"]
            except json.JSONDecodeError:
                self.logger.error("Error parsing JSON: %s", info)
                return {
                    "type": "path",
                    "result": "NOK_JSON",
                }
            return {
                **stats,
                "size": stats["deduplicated_size"],
                "type": "path",
                "result": "OK" if exit_code == "0" else "WARN_EXIT",
            }
        except BackupException as exc:
            if "already exists" in str(exc):
                self.logger.info("Backup already exists")
                return {
                    "type": "stdout",
                    "result": "ALREADY EXISTS",
                }
            else:
                return {
                    "type": "stdout",
                    "result": "NOK_EXCEPTION",
                }

    def backup_stdouts(self):
        if "stdout" not in self.config:
            return
        try:
            self.remote_command(f"mkdir -p {self.tmpdir}")

            for key, value in self.config["stdout"].items():
                stats = self.backup_stdout(key, value)
                self.stats[key] = stats

            outputstats = self.backup_path(self.tmpdir, basename="stdout")
            self.stats["output"] = outputstats

            self.remote_command(f"rm -rf {self.tmpdir}")
        except:
            import traceback

            traceback.print_exc()
            self.stats["output"] = {
                "type": "output",
                "result": "NOK_EXCEPTION",
            }

    def backup_stdout(self, key, value):
        self.remote_command(f"{value}  > {self.tmpdir}/{key}", timeout=25 * 60 * 60)
        size, exit_code = self.remote_command(f"stat -c %s {self.tmpdir}/{key}")
        try:
            int_size = int(size)
        except ValueError:
            self.logger.error("Error parsing size: %s", size)
            return {
                "type": "stdout",
                "result": "NOK_VALUE",
            }
        return {
            "type": "stdout",
            "uncompressed_size": int_size,
            "compressed_size": int_size,
            "deduplicated_size": 0,
            "result": "OK" if exit_code == "0" else "WARN_EXIT",
            "size": int_size,
        }

    def close(self):
        # input("WAITING FOR SOCAT TO CLOSE, PRESS ENTER TO CONTINUE")
        # close socat
        if self.socat:
            logger.debug("Closing socat")
            self.socat.close()
            self.socat = None

        if self.remote:
            logger.debug("Closing remote connection")
            self.remote_command(f"rm -f {self.remote_unix_socket}")
            self.remote.close()
            self.remote = None

    def ensure_repository(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path, exist_ok=True)

        if os.path.exists(f"{self.path}/{self.name}"):
            return

        self.connect_to_host(with_unix_socket=False)
        password = self.get_remote_password()

        logger.info("Creating local repository at %s/%s", self.path, self.name)

        if password:
            logger.info("Reusing password from remote")
        if not password:
            self.logger.info(f"Creating repository for %s at %s", self.name, self.path)
            # do not echo password input
            print()
            print("Creating new repository:")
            print()
            password = input(
                f"Enter password for the repository {self.name}: ",
            )

            logger.debug("Creating password file on remote")
            self.remote_command("mkdir -p ~/.config/coralbackups")
            self.remote.sendline("cat > ~/.config/coralbackups/password")
            self.remote.sendline(password)
            self.remote.sendeof()
            self.remote.expect("::PEXPECT:: ", timeout=10)

        password = password.strip()
        # logger.debug("Repository password: %s", password)

        sh.borg(
            "init",
            "--encryption=repokey",
            f"{self.path}/{self.name}",
            _env={"BORG_PASSPHRASE": password},
        )
        self.disconnect_from_host()
        logger.info("Repository created")

    def get_remote_password(self):
        password, exit_code = self.remote_command(
            "cat ~/.config/coralbackups/password", timeout=60
        )
        if exit_code != "0":
            return None
        return password


class BackupException(Exception):
    pass


def dict_drop(d, *keys):
    ret = {}
    for key, value in d.items():
        if key in keys:
            continue
        ret[key] = value
    return ret


def pretty_size(size, postfixes=["bytes", "kib", "MiB", "GiB", "TiB"]):
    if size < 1024:
        return "%d %s" % (size, postfixes[0])
    return pretty_size(size / 1024, postfixes[1:])


def email_stats(
    *,
    smtp: dict,
    mailto: list[str],
    backupname: str,
    stats: dict,
    total_time: datetime.timedelta,
    send_email: bool = True,
):
    """
    stats is the same format as each server, but with added fields:
    * size
    * result
    * logs

    So for example:

    {
        "coralbits.com": {
            "type": "path",
            "compressed_size": 1234,
            "uncompressed_size": 1234,
            "deduplicated_size": 1234,
        }
    }
    """
    all_ok, htmld = html_table_for_all_hosts(stats)

    htmld = f"<div>Total time: {total_time}</div>{htmld}"

    date = datetime.date.today()
    backupname = os.path.basename(backupname)[:-5]
    title = f"{all_ok} backup {backupname} {date}"

    store_local_file = True
    if store_local_file:
        filename = f"/tmp/{backupname}.html"
        with open(filename, "w", encoding="utf-8") as fd:
            fd.write("<h1>%s</h1>%s" % (title, htmld))
        print("Backup statistics created at file://%s" % os.path.abspath(filename))

    if send_email:
        for email in mailto:
            send_email_to(
                smtp=smtp,
                title=title,
                htmld=htmld,
                mailto=email,
                all_ok=all_ok,
            )


def send_email_to(*, smtp, title, htmld, mailto, all_ok: BackupResult):
    logging.info("Send email statistics to %s: %s" % (mailto, all_ok))
    server = smtplib.SMTP(smtp.get("hostname", "localhost"), smtp.get("port", 587))
    if smtp.get("tls", True):
        server.starttls()
    if smtp.get("username"):
        server.login(smtp.get("username"), smtp.get("password"))
    msg = MIMEMultipart()
    msg["From"] = smtp.get("username", "backups")
    msg["To"] = mailto
    msg["Subject"] = title

    msg.attach(MIMEText(htmld, "html"))

    server.sendmail(smtp.get("username", "backups"), mailto, msg.as_string())
    server.quit()


def create_logs_section():
    """Creates the HTML section with detailed logs."""
    logs_html = f"<hr><div style='{EMAIL_STYLES['logs_container']}'>"
    logs_html += f"<h3 style='{EMAIL_STYLES['logs_header']}'>Detailed Logs</h3>"
    logs_html += f"<div style='{EMAIL_STYLES['logs_box']}'>"
    logs_html += f"<pre style='{EMAIL_STYLES['logs_text']}'>"

    # Keywords that might indicate password content
    password_indicators = [
        "password",
        "passphrase",
        "secret",
        "key",
        "token",
    ]

    for dt, level, line in log_handler.keep:
        # Add HR before "Running backup for:" lines
        if "Running backup for:" in line:
            logs_html += (
                "<hr style='border: 0; border-top: 1px solid #ddd; margin: 10px 0;'>"
            )

        # Check for password mentions and mask them
        masked_line = line
        for indicator in password_indicators:
            if indicator.lower() in line.lower():
                # Mask the entire line if it contains password-related content
                masked_line = "[PASSWORD CONTENT REDACTED]"
                break

        level_name = logging.getLevelName(level)
        logs_html += f"<span style='color: {LOG_COLORS[level]};'>{dt} [{level_name}] {masked_line}</span>\n"

    logs_html += "</pre></div></div>"
    return logs_html


def create_stats_table(stats) -> tuple[BackupResult, str]:
    """Creates the HTML table with backup statistics."""
    table = f"<table style='{EMAIL_STYLES['table']}'><thead>"
    table += f"<tr style='{EMAIL_STYLES['table_header']}'><th>Host</th><th>Area</th>"
    table += "<th>Item</th><th>Result</th><th>Size</th></tr>"
    table += "</thead>\n"

    all_ok = BackupResult()
    for host, host_stats in stats.items():
        all_ok2, ntable = html_table_for_host(host, host_stats)
        all_ok.update(all_ok2)
        table += ntable

    table += "</table>"
    return all_ok, table


def create_email_header():
    """Creates the header section of the email."""
    return f"<div style='{EMAIL_STYLES['header']}'>Backup results at {datetime.datetime.now()}</div>"


def html_table_for_all_hosts(stats) -> tuple[BackupResult, str]:
    """Main function to generate the complete HTML email content."""
    all_ok, table = create_stats_table(stats)

    htmld = f"<div style='{EMAIL_STYLES['container']}'>"
    htmld += create_email_header()
    htmld += table
    htmld += create_logs_section()
    htmld += "</div>"

    return all_ok, htmld


def html_table_for_host(host: str, stats: dict) -> tuple[BackupResult, str]:
    all_ok = BackupResult()
    table = ""
    for path, stats in stats.items():
        table += f"<tr style='{EMAIL_STYLES['table_cell']}'>"
        table += f"<td style='{EMAIL_STYLES['table_cell']}'>{host}</td>"
        table += f"<td style='{EMAIL_STYLES['table_cell']}'>{stats['type']}</td>"
        table += f"<td style='{EMAIL_STYLES['table_cell']}'>{path}</td>"
        if stats["result"] == "OK":
            table += f"<td style='{EMAIL_STYLES['table_cell']} {EMAIL_STYLES['success_cell']}'>{stats['result']}</td>"
        elif stats["result"].startswith("WARN"):
            table += f"<td style='{EMAIL_STYLES['table_cell']} {EMAIL_STYLES['warning_cell']}'>{stats['result']}</td>"
            all_ok.update(stats["result"])
        else:
            table += f"<td style='{EMAIL_STYLES['table_cell']} {EMAIL_STYLES['error_cell']}'>{stats['result']}</td>"
            all_ok.update(stats["result"])
        if "size" in stats and stats["size"] is not None:
            table += f"<td style='{EMAIL_STYLES['table_cell']}'>{pretty_size(stats['size'])}</td>"
        table += "</tr>\n"
    return all_ok, table


if __name__ == "__main__":
    Backup().run()
