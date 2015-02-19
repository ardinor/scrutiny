# -*- coding: utf-8 -*-
import unittest

from datetime import datetime
from sqlalchemy.exc import IntegrityError

from scrutiny import Scrutiny
from scrutiny.models import IPAddr, BannedIPs, BreakinAttempts, Base, \
    SubnetDetails

class TestCase(unittest.TestCase):

    def setUp(self):
        self.scrutiny_instance = Scrutiny()
        self.scrutiny_instance.create_db()
        self.session = self.scrutiny_instance.session
        self.base = self.scrutiny_instance.base
        self.engine = self.scrutiny_instance.engine


    def tearDown(self):
        self.base.metadata.drop_all(self.engine)


    def test_IPAddr(self):
        addr = '127.0.0.1'
        test_ip = IPAddr(addr)
        test_ip.city_name = 'Darujhistan'
        test_ip.region = 'Lake Azur'
        test_ip.county = 'Genabackis'
        self.session.add(test_ip)
        self.session.commit()

        ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr=='127.0.0.1').first()
        self.assertEqual(ip_addr.ip_addr, addr)

        # Test UTF-8
        region = 'ララク'
        country = 'ゲンアバキス'
        test_ip2 = IPAddr('127.0.0.125')
        test_ip2.region = region
        test_ip2.country = country
        self.session.add(test_ip2)
        self.session.commit()

        ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr=='127.0.0.125').first()
        self.assertEqual(ip_addr.region, region)
        self.assertEqual(ip_addr.country, country)

    def test_IPAddr_integrity(self):
        test_ip = IPAddr('127.0.0.1')
        test_ip.city_name = 'Darujhistan'
        test_ip.region = 'Lake Azur'
        test_ip.county = 'Genabackis'
        self.session.add(test_ip)
        self.session.commit()

        test_ip2 = IPAddr('127.0.0.1')
        self.session.add(test_ip2)
        self.assertRaises(IntegrityError, self.session.commit)
        self.session.rollback()


    def test_BreakinAttempts(self):

        test_ip = IPAddr('127.0.0.1')
        self.session.add(test_ip)
        self.session.commit()

        ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr=='127.0.0.1').first()
        attempt_date = datetime.now().replace(day=1)
        breakin1 = BreakinAttempts(date=attempt_date, user='test')
        breakin1.ipaddr = ip_addr.id
        self.session.add(breakin1)
        self.session.commit()

    def test_BannedIPs(self):

        test_ip = IPAddr('127.0.0.1')
        self.session.add(test_ip)
        self.session.commit()

        ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr=='127.0.0.1').first()
        attempt_date = datetime.now()
        ban1 = BannedIPs(date=attempt_date)
        ban1.ipaddr = ip_addr.id
        self.session.add(ban1)
        self.session.commit()



if __name__ == '__main__':
    unittest.main()
