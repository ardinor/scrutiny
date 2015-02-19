# -*- coding: utf-8 -*-
import unittest

from datetime import datetime
from sqlalchemy.exc import IntegrityError

from scrutiny import Scrutiny
from scrutiny import IPAddr, BannedIPs, BreakinAttempts, Base, SubnetDetails

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

    def test_Subnets(self):

        for ip in ['192.168.1.1', '192.168.1.30', '192.168.1.26']:
            test_ip = IPAddr(ip)
            self.session.add(test_ip)
            self.session.commit()

            for i in range(3):
                attempt_date = datetime.now().replace(minute=i+1)
                breakin = BreakinAttempts(date=attempt_date, user='test')
                breakin.ipaddr = test_ip.id
                self.session.add(breakin)
                self.session.commit()

        self.scrutiny_instance.calculate_common_subnets()
        subnet = self.session.query(SubnetDetails)
        self.assertEqual(subnet.count(), 1)
        subnet = subnet.first()
        self.assertEqual(subnet.subnet_id, '192.168.1.0')
        self.assertEqual(subnet.cidr, '/27')
        self.assertEqual(subnet.netmask, '255.255.255.224')
        self.assertEqual(subnet.number_hosts, 30)
        #self.session.delete(subnet)
        #self.session.commit()

        for ip in ['172.16.64.1', '172.16.111.30', '172.16.123.26']:
            test_ip = IPAddr(ip)
            self.session.add(test_ip)
            self.session.commit()

            for i in range(3):
                attempt_date = datetime.now().replace(minute=i+1)
                breakin = BreakinAttempts(date=attempt_date, user='test')
                breakin.ipaddr = test_ip.id
                self.session.add(breakin)
                self.session.commit()

        self.scrutiny_instance.calculate_common_subnets()
        subnet = self.session.query(SubnetDetails).filter(SubnetDetails.subnet_id=='172.16.64.0')
        self.assertEqual(subnet.count(), 1)
        self.assertIsNotNone(subnet.first)
        subnet = subnet.first()
        self.assertEqual(subnet.subnet_id, '172.16.64.0')
        self.assertEqual(subnet.cidr, '/18')
        self.assertEqual(subnet.netmask, '255.255.192.0')
        self.assertEqual(subnet.number_hosts, 16382)






if __name__ == '__main__':
    unittest.main()
