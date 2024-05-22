#!/usr/bin/env python3
import logging
import argparse
import os
import traceback
import pexpect
import sh
import datetime

import yaml


logger = logging.getLogger("backup-borg")

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

    def __init__(self):
        self.parse_args()
        self.parse_yaml()
        self.plan = None
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

    def run(self):
        logger.info(f"Running backup with %s at %s", self.options.yamlfile, self.path)
        for server in self.servers:
            self.backup(server)

    def backup(self, server: str):
        BackupServer(
            name=server,
            config=self.servers[server],
            path=self.path,
            options=self.options,
        ).run()


class BackupServer:
    socat = None
    remote = None
    remote_unix_socket = None
    local_unix_socket = None

    def __init__(self, *, name: str, config: dict, options: dict, path: str):
        self.logger = logging.getLogger(name)
        self.name = name
        self.config = config
        self.path = path
        self.options = options
        self.remote_unix_socket = f"/tmp/{self.name}.sock"
        self.local_unix_socket = f"{self.path}/{self.name}.sock"
        self.logger.debug(
            "Remote unix socket: %s <-> %s",
            self.remote_unix_socket,
            self.local_unix_socket,
        )

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
        finally:
            self.close()
        self.logger.info("Backup finished")

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

    def remote_command(self, cmd, timeout=10):
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
                self.backup_path(path)
            except Exception as e:
                traceback.print_exc()
                self.logger.error("Error backing up %s", path)

    def backup_path(self, path):
        self.logger.info("Backing up %s", path)
        backupname = (
            f"{datetime.datetime.now().strftime('%Y%m%d%H%M')}-{path.replace('/', '-')}"
        )
        while backupname.endswith("-"):
            backupname = backupname[:-1]

        try:
            self.remote_command(
                f"borg create 'ssh://borg-server/{self.path}/{self.name}::{backupname}' '{path}'",
                timeout=24 * 60 * 60,
            )
        except BackupException as exc:
            if "already exists" in str(exc):
                self.logger.info("Backup already exists")
            else:
                raise

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


if __name__ == "__main__":
    Backup().run()
