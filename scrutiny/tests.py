# -*- coding: utf-8 -*-
import unittest
from datetime import timedelta, datetime

from scrutiny import Scrutiny
from scrutiny.models import IPAddr, BannedIPs, BreakinAttempts

def populate_test_data(session):

    last_month = datetime.now().replace(day=1) - timedelta(days=1)

    sample_ip_data = {
        '192.168.1.1': ['McMurdo', 'Antartica'],
        '10.0.0.1': ['Luxembourg City', 'Luxembourg'],
        '172.16.0.1': ['大阪', '日本'],
        '172.16.0.56': ['熊本県', '日本'],
        '163.12.76.193': ['Düsseldorf', 'Germany'],
        '163.12.76.222': ['Düsseldorf', 'Germany'],
        '74.123.51.130': ['Ljubljana', 'Slovenia'],
        '74.123.51.139': ['Ljubljana', 'Slovenia'],
        '74.123.51.240': ['Ljubljana', 'Slovenia'],
        '74.123.51.251': ['Ljubljana', 'Slovenia'],
    }

    sample_attempts = {
        '192.168.1.1': ['admin', 'admin', 'admin', 'admin'],
        '10.0.0.1': ['oracle', 'nagios', 'aaa'],
        '172.16.0.1': ['aaa', 'aaa', 'aaa'],
        '172.16.0.56': ['qwe', 'qwe', 'qwe'],
        '163.12.76.193': ['wertwasdcw', 'Hanz', 'Hanz', 'Prometheus'],
        '163.12.76.222': ['asdqwqwqq', 'bob'],
        '74.123.51.130': ['abebrabr', 'abebrabr', 'aberbaerb', 'aberbaerb', 'aberbaerb'],
        '74.123.51.139': ['abebrabr', 'abebrabr', 'aberbaerb'],
        '74.123.51.240': ['abebrabr', 'abebrabr', 'aberbaerb'],
        '74.123.51.251': ['abebrabr', 'abebrabr', 'aberbaerb'],
    }

    sample_bans = [
        '192.168.1.1',
    ]

    for i, j in sample_ip_data.items():

        ip_entry = IPAddr(i)
        ip_entry.region = j[0]
        ip_entry.country = j[1]
        session.add(ip_entry)
        session.commit()

        for user in sample_attempts[i]:
            attempt = BreakinAttempts(date=last_month, user=user)
            attempt.ip = ip_entry
            session.add(attempt)
        session.commit()

        if i in sample_bans:
            sample_ban = BannedIPs(date=last_month)
            sample_ban.ipaddr = ip_entry.id
            session.add(sample_ban)
            session.commit()

def populate_test_tz_data():

    if time.localtime().tm_isdst:
        displayed_time = time.tzname[time.daylight]
        time_offset = (time.altzone * -1) / 3600
    else:
        displayed_time = time.tzname[0]
        time_offset = (time.timezone * -1) / 3600

    if time_offset > 0:
        time_offset = '+{}'.format(time_offset)

    return displayed_time, time_offset, None

class TestCase(unittest.TestCase):

    def setUp(self):
        s = Scrutiny()
        # create dbs

    def tearDown(self):
        # drop tables

    def testIPAddr(self):

