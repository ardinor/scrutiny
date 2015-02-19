# -*- coding: utf-8 -*-
import unittest

from scrutiny import Scrutiny
from scrutiny.models import IPAddr, BannedIPs, BreakinAttempts, Base, \
    SubnetDetails

class TestCase(unittest.TestCase):

    def setUp(self):
        self.scrutiny_instance = Scrutiny()
        self.scrutiny_instance.create_db()


    def tearDown(self):
        self.scrutiny_instance.delete_db()


    def testIPAddr(self):
        test_ip = IPAddr()

