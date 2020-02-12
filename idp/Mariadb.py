#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       Copyright 2017 Ahmed Nazmy
#

# Meta

from IdPFactory import IdP
import logging

import MySQLdb as mc


class Mariadb(IdP):
    """
    Fetch the authority information from a Mariadb Server
    """

    __db = None
    __host = ""
    __user = ""
    __pass = ""
    __database = ""
    
    _allowed_ssh_hosts = list()

    def __init__(self, config, username, gateway_hostgroup):
        super(Mariadb, self).__init__(username, gateway_hostgroup)
        logging.info("Mariadb: loaded")
        self.config = config
        self.posix_user = username
        self._init_mariadb()

    def __connect(self):
        try:
            self.__db = mc.connect(self.__host, self.__user, self.__pass, self.__database)
            logging.debug("Mariadb: Connection successfull")
            return True
        except Exception as e:
            logging.error(
                "MARIADB: Could not connect to database, error : {0}".format(
                    e))
            return False

    def _init_mariadb(self):
        # Load the configration from the already intitialised config parser
        self.__host = self.config.get("Mariadb", "host", "")
        self.__user = self.config.get("Mariadb", "user", "")
        self.__pass = self.config.get("Mariadb", "password", "")
        self.__database = self.config.get("Mariadb", "database", "")

        if self.__host and self.__user and self.__database:
            self._load_user_allowed_hosts()

    def _load_user_allowed_hosts(self):
        if not self.__connect():
            return
        logging.debug("Mariadb: Loading all hosts for user {0} from {1}".format(self.posix_user, self.__database))
        req = """SELECT h.name, h.hostname, h.port, hg.name as hostgroup FROM hosts as h
            JOIN hosts_hostgroups as hh ON hh.hostsId = h.id
            JOIN hostgroups as hg ON hg.id = hh.hostgroupsId
            JOIN hosts_usergroups as hu ON h.id = hu.hostsId
            WHERE hu.usergroupsId IN
                (SELECT usergroupsId FROM users_usergroups as uu JOIN users ON uu.usersId = users.id AND users.username = '""" + self.posix_user + "');"
        try:
            res = {}
            cur = self.__db.cursor(mc.cursors.DictCursor)
            cur.execute(req)
            res = cur.fetchall()
            cur.close()
        except Exception as e:
            if cur is not None:
                cur.close()
            if self.__db is not None:
                self.__db.close()
            res = {}
            logging.error(
                    "Mariadb: Error retrieving data from mariadb {0}".format(
                        e))
        else:
            self.__db.close()
        self._parse_hosts(res)

    def _parse_hosts(self, res):
        """
        Fetch the allowed hosts based usergroup/hostgroup membership
        """
        for data in res:
            if data["name"] not in self._allowed_ssh_hosts :
                logging.debug("Mariadb: Loading host {0} for user {1}".format(
                    data["name"], self.posix_user))
                self._allowed_ssh_hosts[data["name"]] = {
                    'name': data["name"],
                    'fqdn': data["hostname"],
                    'ssh_port': data["port"],
                    'hostgroups': [data["hostgroup"]]
                }
            else:
                if data["hostgroup"] not in self._allowed_ssh_hosts[data["name"]]["hostgroups"]:
                    self._allowed_ssh_hosts[data["name"]]["hostgroups"].append(data["hostgroup"])

    def list_allowed(self):
        # is our list empty ?
        if not self._allowed_ssh_hosts:
            self._load_user_allowed_hosts()
        return self._allowed_ssh_hosts

