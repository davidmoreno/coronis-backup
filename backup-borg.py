#!/usr/bin/env python3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import logging
import argparse
import os
import smtplib
import traceback
import datetime
import pexpect
import sh

import yaml


# Custom logger class with multiple destinations
class ColoredHandlerAndKeep(logging.Handler):
    LEVEL_TO_COLOR = {
        0: "\033[0;36m",
        10: "\033[0;34m",
        20: "\033[1;m",
        30: "\033[0;33m",
        40: "\033[0;31m",
        50: "\033[1;31m",
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


log_handler = ColoredHandlerAndKeep()
logger = logging.getLogger("backup-borg")
# logger.addHandler(log_handler)

logging.basicConfig(level=logging.DEBUG)

SSH_ARGS = [
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
]


class Backup:
    options: dict
    plan: dict
    tobackup: list
    servers: list[str, dict]
    path: str
    mailto: list
    stats: dict
    smtp: dict

    def __init__(self):
        self.parse_args()
        self.parse_yaml()
        self.stats = {}
        self.mailto = []
        logger.debug("options: %s", self.options)
        logger.debug("servers: %s", self.servers)

    def parse_args(self):
        args = argparse.ArgumentParser(description="Backup script using borg backup")
        args.add_argument("yamlfile", help="YAML file with backup configuration")
        args.add_argument(
            "servernames", nargs="*", help="YAML file with backup configuration"
        )
        args.add_argument("--verbose", action="store_true", help="Verbose output")

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
        logger.info(f"Running backup with %s at %s", self.options.yamlfile, self.path)
        self.stats = {}
        for server in self.servers:
            self.backup(server)
        self.send_stats_email()

    def backup(self, server: str):
        self.stats[server] = BackupServer(
            name=server,
            config=self.servers[server],
            path=self.path,
            options=self.options,
        ).run()

    def send_stats_email(self):
        email_stats(
            mailto=self.mailto,
            backupname=self.options.yamlfile,
            stats=self.stats,
            smtp=self.smtp,
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
        self.remote_unix_socket = f"/tmp/{self.name}.sock"
        self.local_unix_socket = f"{self.path}/{self.name}.sock"
        self.tmpdir = "/tmp/coralbackups/"
        self.logger.debug(
            "Remote unix socket: %s <-> %s",
            self.remote_unix_socket,
            self.local_unix_socket,
        )
        self.stats = {}

    def run(self):
        self.logger.info(
            f"Running backup for: %s with config: %s", self.name, self.config
        )
        try:
            self.ensure_repository()
            self.prepare_socat()
            self.connect_to_host()
            self.setup_remote_borg_envvars()

            self.backup_paths()
            self.backup_stdouts()
        finally:
            self.close()
        self.logger.info("Backup finished")
        return self.stats

    def prepare_socat(self):
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

    def connect_to_host(self):
        user = self.config["auth"]["user"]
        server = self.name
        sudo = []
        if "become" in self.config["auth"]:
            sudo = self.config["auth"]["become"].split(" ")

        cmd = [
            "ssh",
            "-R",
            f"{self.remote_unix_socket}:{self.local_unix_socket}",
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

    def remote_command(self, cmd, timeout=10) -> str:
        self.logger.debug("Executing remote command: %s", cmd)
        self.remote.sendline(cmd)
        self.remote.expect("::PEXPECT:: ", timeout=timeout)
        stdout = self.remote.before
        self.remote.sendline("echo ERROR CODE $?")
        self.remote.expect(r"ERROR CODE (\d+)", timeout=10)
        if self.remote.match.group(1) != "0":
            self.logger.error("Error in command: \n%s", stdout)
            raise BackupException(
                "Error in borg command, %s" % self.remote.match.string
            )
        self.remote.expect("::PEXPECT:: ", timeout=10)
        stdout = stdout[stdout.index("\n") + 1 :]

        return stdout

    def setup_remote_borg_envvars(self):
        # ensure socket exists
        try:
            self.remote_command(f"test -e /tmp/{self.name}.sock")
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
            info = self.remote_command(
                f"borg create --json 'ssh://borg-server/{self.path}/{self.name}::{backupname}' '{path}'",
                timeout=24 * 60 * 60,
            )
            stats = json.loads(info)["archive"]["stats"]
            return {
                **stats,
                "size": stats["deduplicated_size"],
                "type": "path",
                "result": "OK",
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
                    "result": "NOK",
                }

    def backup_stdouts(self):
        if "stdout" not in self.config:
            return
        self.remote_command(f"mkdir -p {self.tmpdir}")
        for key, value in self.config["stdout"].items():
            stats = self.backup_stdout(key, value)
            self.stats[key] = stats

        outputstats = self.backup_path(self.tmpdir, basename="stdout")
        self.stats["output"] = outputstats

        self.remote_command(f"rm -rf {self.tmpdir}")

    def backup_stdout(self, key, value):
        try:
            self.remote_command(f"{value}  > {self.tmpdir}/{key}")
            size = self.remote_command(f"stat -c %s {self.tmpdir}/{key}")
            return {
                "type": "stdout",
                "uncompressed_size": int(size),
                "compressed_size": int(size),
                "deduplicated_size": 0,
                "result": "OK",
                "size": int(size),
            }
        except:
            self.logger.error("Error backing up stdout %s", key)
            return {
                "type": "stdout",
                "result": "NOK",
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
            self.remote_command(f"rm -f /tmp/{self.name}.sock")
            self.remote.close()
            self.remote = None

    def ensure_repository(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path, exist_ok=True)

        if os.path.exists(f"{self.path}/{self.name}"):
            return

        self.logger.info(f"Creating repository for %s at %s", self.name, self.path)
        # do not echo password input
        print()
        print("Creating new repository:")
        print()
        password = input(
            f"Enter password for the repository {self.name}: ",
        )
        ret = sh.borg(
            "init",
            "--encryption=repokey",
            f"{self.path}/{self.name}",
            _env={"BORG_PASSPHRASE": password},
        )
        logger.debug("borg init: %s", ret)

        self.connect_to_host()

        logger.debug("Creating password file on remote")
        self.remote_command("mkdir -p ~/.config/coralbackups")
        self.remote.sendline("cat > ~/.config/coralbackups/password")
        self.remote.sendline(password)
        self.remote.sendeof()
        self.remote.expect("::PEXPECT:: ", timeout=10)
        self.remote.close()


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


def email_stats(*, smtp: dict, mailto: list[str], backupname: str, stats: dict):
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

    title = "Backup %s: %s" % (
        datetime.date.today(),
        "Ok" if all_ok else "Error",
    )

    store_local_file = True
    send_email = True
    if store_local_file:
        filename = "/tmp/" + os.path.basename(backupname)[:-5] + ".html"
        with open(filename, "w", encoding="utf-8") as fd:
            fd.write("<h1>%s</h1>%s" % (title, htmld))
        print("Backup statistics created at file://%s" % os.path.abspath(filename))

    if send_email:
        for email in mailto:
            send_email_to(
                smtp=smtp,
                backupname=backupname,
                title=title,
                htmld=htmld,
                mailto=email,
                all_ok=all_ok,
            )


def send_email_to(*, smtp, backupname, title, htmld, mailto, all_ok):
    logging.info(
        "Send email statistics to %s: %s" % (backupname, "OK" if all_ok else "ERROR")
    )
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


def html_table_for_all_hosts(stats):
    LEVEL_TO_COLOR = {
        0: "blue",
        10: "blue",
        20: "white",
        30: "#fbbd08",
        40: "#db2828",
        50: "#db2828",
    }

    table = (
        "<table style='border-collapse: collapse; border: 1px solid #2185d0;'><thead>"
    )
    table += "<tr style='background: #2185d0; color:white; '><th>Host</th><th>Area</th>"
    table += "<th>Item</th><th>Result</th><th>Size</th></tr>"
    table += "</thead>\n"

    all_ok = True
    for host, stats in stats.items():
        all_ok2, ntable = html_table_for_host(host, stats)
        all_ok = all_ok and all_ok2
        table += ntable

    table += "</table>"

    htmld = "<div style='font-family: Sans Serif;'>"
    htmld += (
        "<div style='padding-bottom: 20px;'>Backup results at %s</div>"
        % datetime.datetime.now()
    )
    htmld += table

    htmld += "<hr><div style='background: #333;'>"
    for dt, level, line in log_handler.keep:
        htmld += "<pre style='color: %s; margin: 0;'>%s - %s</pre>\n" % (
            LEVEL_TO_COLOR[level],
            dt,
            line,
        )

    htmld += "</div></div>"

    return all_ok, htmld


def html_table_for_host(host: str, stats: dict):
    all_ok = True
    table = ""
    for path, stats in stats.items():
        table += "<tr style='border: 1px solid #2185d0;'>"
        table += "<td style='border: 1px solid #2185d0; padding: 5px;'>%s</td>" % host
        table += (
            "<td style='border: 1px solid #2185d0; padding: 5px;'>%s</td>"
            % stats["type"]
        )
        table += "<td style='border: 1px solid #2185d0; padding: 5px;'>%s</td>" % path
        if stats["result"] == "OK":
            table += (
                "<td style='border: 1px solid #2185d0; padding: 5px; background: #21ba45;''>%s</td>"
                % stats["result"]
            )
        else:
            table += (
                "<td style='border: 1px solid #2185d0; padding: 5px; background: #db2828;'>%s</td>"
                % stats["result"]
            )
            all_ok = False
        if "size" in stats and stats["size"] is not None:
            table += (
                "<td style='border: 1px solid #2185d0; padding: 5px;'>%s</td>"
                % pretty_size(stats["size"])
            )
        table += "</tr>\n"
    return all_ok, table


if __name__ == "__main__":
    Backup().run()
