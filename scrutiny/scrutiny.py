import re
import gzip
import os
import time
import json
import codecs
import urllib.request, urllib.parse  # urllib.error
import pytz
import logging
import sys
from socket import gethostname
from datetime import timedelta, datetime
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from math import log

from scrutiny.models import IPAddr, BannedIPs, BreakinAttempts, Base, \
    SubnetDetails
from scrutiny.settings import API_URL, API_KEY, LOG_DIR, SEARCH_STRING, \
    FAIL2BAN_SEARCH_STRING, ROOT_NOT_ALLOWED_SEARCH_STRING, DATABASE_URI, \
    DEBUG
from scrutiny.tests import populate_test_data, populate_test_tz_data


class Scrutiny():

    def __init__(self):
        self.engine = self.get_engine()
        self.base = Base
        self.session = self.get_session(Base, self.engine)

        self.logger = logging.getLogger('scrutiny')
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] - %(message)s')
        stream_handler = logging.StreamHandler(stream=sys.stdout)
        stream_handler.setFormatter(formatter)
        if DEBUG:
            stream_handler.setLevel(logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)
        else:
            stream_handler.setLevel(logging.INFO)
            self.logger.setLevel(logging.INFO)
        self.logger.addHandler(stream_handler)


    def get_engine(self):
        return create_engine(DATABASE_URI)


    def get_session(self, base, engine):
        Session = sessionmaker()
        Session.configure(bind=engine)
        base.metadata.create_all(engine)

        return Session()


    def create_db(self):
        self.base.metadata.create_all(self.engine)


    def delete_db(self):
        self.base.metadata.drop_all(self.engine)


    def tz_setup(self):
        if time.localtime().tm_isdst:
            displayed_time = time.tzname[time.daylight]
            time_offset = (time.altzone * -1) / 3600
        else:
            displayed_time = time.tzname[0]
            time_offset = (time.timezone * -1) / 3600

        if time_offset > 0:
            time_offset = '+{}'.format(time_offset)

        #Get zone info (aka just set the system time to UTC already)
        #a = os.popen("cat /etc/sysconfig/clock | grep ZONE")  # RHEL
        a = os.popen("cat /etc/timezone")   # Debian
        cat_res = a.read()
        if cat_res:
            #cat_res = cat_res.replace('ZONE="', '')  # Debian doesn't need this
            cat_res = cat_res.replace('"\n', '')
            try:
                sys_tz = pytz.timezone(cat_res)
            except pytz.UnknownTimeZoneError:
                # Couldn't get the time zone properly
                sys_tz = None
        else:
            sys_tz = None

        return displayed_time, time_offset, sys_tz


    def check_ip_location(self, ip):

        if DEBUG:
            # Do some stuff for testing here
            return_dict = {}
            return return_dict
        else:
            params = {'format': 'json', 'key': API_KEY, 'ip': ip, 'timezone': 'false'}
            self.logger.debug('Checking IP - {}'.format(ip))
            url_params = urllib.parse.urlencode(params)
            url = API_URL + '?' + url_params
            url_obj = urllib.request.urlopen(url)
            response = url_obj.read()
            try:
                response = response.decode("utf-8") # response is bytes, parse to string
            except AttributeError:
                pass
            url_obj.close()
            response_dict = json.loads(response)

            return_dict = {}

            if 'cityName' in response_dict and response_dict['cityName'] != '-':
                return_dict['region'] = response_dict['cityName'] + ', ' + response_dict['regionName']
            elif 'regionName' in response_dict and response_dict['regionName'] != '-':
                return_dict['region'] = response_dict['regionName']
            else:
                return_dict['region'] = '-'

            if 'countryName' in response_dict:
                return_dict['country'] = response_dict['countryName']
            else:
                return_dict['country'] = '-'

            self.logger.debug('Location - {} {}'.format(return_dict['region'], return_dict['country']))

            time.sleep(2)

        return return_dict


    def parse_content(self, content, breakin_attempt, banned_ip, last_month, auth_log):

        for line in content:
            if auth_log:
                # Catch the usual
                # Jun 10 12:40:05 defestri sshd[11019]: Invalid user admin from 61.174.51.217
                m = re.search(SEARCH_STRING, line)
                if m is None:
                    # Also catch these
                    # Jun  8 04:31:10 defestri sshd[5013]: User root from 116.10.191.234 not allowed because none of user's groups are listed in AllowGroups
                    m = re.search(ROOT_NOT_ALLOWED_SEARCH_STRING, line)
                if m:
                    if m.group('log_date')[:3] == last_month.strftime('%b'):
                        log_date = datetime.strptime(m.group('log_date'), '%b %d %H:%M:%S')
                        log_date = log_date.replace(year=last_month.year)
                        # Set the time zone info for the system
                        #log_date = log_date.replace(tzinfo=sys_tz)
                        # Convert it to UTC time
                        #log_date = log_date.astimezone(pytz.utc)

                        #sometimes there's multiple entries per second, since we're
                        #not that concerned about to the second accuracy just increment
                        #the seconds until we find a unique log date to put in
                        if log_date in breakin_attempt:
                            while log_date in breakin_attempt:
                                ns = log_date.second+1
                                if ns >= 60:
                                    ns = 0
                                log_date = log_date.replace(second=ns)
                        breakin_attempt[log_date] = (m.group('ip_add'), m.group('user'))

            else:
                m = re.search(FAIL2BAN_SEARCH_STRING, line)
                if m:
                        ban_time = datetime.strptime(m.group('log_date'),
                                                     '%Y-%m-%d %H:%M:%S,%f')
                        if ban_time.month == last_month.month:
                            banned_ip[ban_time] = m.group('ip_add')


        return breakin_attempt, banned_ip


    def read_logs(self, log_dir):

        banned_ip = {}
        breakin_attempt = {}

        last_month = datetime.now().replace(day=1) - timedelta(days=1) #.strftime('%b')
        two_month_ago = last_month.replace(day=1) - timedelta(days=1)

        for log_file in os.listdir(log_dir):
            if 'auth.log' in log_file or 'fail2ban.log' in log_file:
                modified_date = datetime.strptime(time.ctime(os.path.getmtime(
                                os.path.join(log_dir, log_file))), "%a %b %d %H:%M:%S %Y")
                if  modified_date > two_month_ago:
                    if 'auth.log' in log_file:
                        auth_log = True
                    else:
                        auth_log = False
                    if os.path.splitext(log_file)[1] == '.gz':
                        # Use zcat?
                        f = gzip.open(os.path.join(log_dir, log_file), 'r')
                        file_content = f.read()  # comes out as bytes
                        try:
                            file_content = file_content.decode("utf-8") # convert to a string
                        except AttributeError:
                            pass # wasn't bytes, ignore
                        split_text = file_content.split('\n')
                        breakin_attempt, banned_ip = self.parse_content(split_text,
                                                                        breakin_attempt,
                                                                        banned_ip,
                                                                        last_month,
                                                                        auth_log)

                    else:
                        with open(os.path.join(log_dir, log_file), 'r') as f:
                            breakin_attempt, banned_ip = self.parse_content(f,
                                                                            breakin_attempt,
                                                                            banned_ip,
                                                                            last_month,
                                                                            auth_log)

        return breakin_attempt, banned_ip


    def create_new_ipaddr(self, ip):

        ip_addr = IPAddr(ip)
        location = self.check_ip_location(ip)
        if 'region' in location:
            ip_addr.region = location['region']
        if 'country' in location:
            ip_addr.country = location['country']
        self.session.add(ip_addr)
        self.session.commit()

        return ip_addr


    def insert_into_db(self, ips, breakin_attempts, bans):

        ip_items = {}

        #return_dict = self.check_ip_location(i)
        # {ip: {region: '', country: ''}}

        for ip in ips:
            # Query to see if already exists first
            ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr==ip)
            if ip_addr.count() == 0:
                self.create_new_ipaddr(ip)
            else:
                ip_addr = ip_addr.first()
            ip_items[ip] = ip_addr.id

        for attempt_date, attempt_details in breakin_attempts.items():
            # e.g. attempt_details = ('127.0.0.1', 'root')

            breakin = self.session.query(BreakinAttempts).filter(BreakinAttempts.date==attempt_date). \
                filter(BreakinAttempts.user==attempt_details[1])
            # If it already exists in the db don't add it again
            if breakin.count() == 0:
                new_attempt = BreakinAttempts(date=attempt_date,
                    user=attempt_details[1])
                new_attempt.ipaddr = ip_items[attempt_details[0]]
                self.session.add(new_attempt)
                self.session.commit()

        for banned_date, banned_ip in bans.items():
            # In some instances it references a ban that doesn't have the IP
            # in ip_items?
            try:
                ban = self.session.query(BannedIPs).filter(BannedIPs.date==banned_date). \
                    filter(BannedIPs.ipaddr.ip_addr==banned_ip)
            # AttributeError: Neither 'InstrumentedAttribute' object nor 'Comparator' object associated with BannedIPs.ipaddr has an attribute 'ip_addr'
            # Caused by the ban existing but not having an IPAddr associated with it I think
            # Ugly work around, maybe change the query
            # ban = self.session.query(BannedIPs).filter(BannedIPs.date==banned_date). \
            # join(IPAddr)
            except AttributeError:
                # Make a new type of list inheriting from the builtin list
                # this makes the below check (ban.count() == 0) work
                # This is pretty silly but sometimes doing things the easy way
                # is for chumps
                class nList(list):
                    def count(self):
                        return len(self)
                ban = nList()
            # If it already exists in the db don't add it again
            if ban.count() == 0:
                new_ban = BannedIPs(date=banned_date)
                if banned_ip in ip_items:
                    new_ban.ipaddr = ip_items[banned_ip]
                else:
                    # Check ip location and make new IPAddr item here
                    ip_addr = self.create_new_ipaddr(banned_ip)
                    new_ban.ipaddr = ip_addr.id
                self.session.add(new_ban)
                self.session.commit()


    def convert_ip_string_to_binary(self, ip_addr):

        """
        Converts an IP address formatted as a string i.e. '74.123.51.130'
        to its binary representation (formatted as a string) '1001010111101111001110000010'
        Will I use this?
        """

        ip_list = ip_addr.split('.')
        bin_list = []
        for i in ip_list:
            bin_list.append("{0:b}".format(int(i)))
        return ''.join(bin_list)


    def compare_ip_strings(self, ip_addr1, ip_addr2):
        ip_list1 = ip_addr1.split('.')
        ip_list2 = ip_addr2.split('.')
        for index, i in enumerate(ip_list1):
            if int(i) != int(ip_list2[index]):
                if index == 1:
                    '/8 is different'
                    return 8
                elif index == 2:
                    '/16 is different'
                    return 16
                elif index == 3:
                    '/24 is different'
                    return 24
                else:
                    'The first octet is different, completely different addresses'
                    return 0


    def get_first_16_bits(self, ip_addr):
        split_ip = ip_addr.split('.')
        return split_ip[0] + '.' + split_ip[1]


    def get_first_24_bits(self, ip_addr):
        reverse_ip = ip_addr[::-1]
        split_ip_24 = reverse_ip[reverse_ip.find('.')+1:]
        return split_ip_24[::-1]


    def calculate_network_details(self, network_prefix, ip_list, sixteen=False, twentyfour=False):

        if sixteen is False and twentyfour is False:
            raise Exception("Either sixteen or twentyfour needs to be True")

        ip_range = []
        for ip in ip_list:
            if sixteen:
                self.logger.debug(ip)
                split_ip = ip.split('.')
                ip_range += [int(split_ip[2])] # get the third item
            elif twentyfour:
                split_ip = ip.split('.')
                ip_range += [int(split_ip[3])]  # get the third item
        if sixteen:
            self.logger.debug(ip_range)

        # Find the difference between the highest and lowest IPs seen
        ip_range_diff = max(ip_range) - min(ip_range)
        # Find the nearest power of 2 (credit to http://mccormick.cx/news/entries/nearest-power-of-two)
        subnet_range = pow(2, int(log(ip_range_diff, 2) + 0.5))
        # Calculate the net mask, it'll be 256 - the subnet range (e.g. 256 - 64 = 192)
        if sixteen:
            netmask = '255.255.{}.0'.format(256 - subnet_range)
        elif twentyfour:
            netmask = '255.255.255.{}'.format(256 - subnet_range)

        # Calculate the CIDR notation
        cidr = 8 - int(log(ip_range_diff, 2) + 0.5)

        # Calculate the number of hosts
        no_hosts = pow(2, 8 - cidr) - 2

        # Format the CIDR to a string '/xx'
        if sixteen:
            cidr = '/{}'.format(16 + cidr)
        elif twentyfour:
            cidr = '/{}'.format(24 + cidr)

        # Next work out the subnet id
        range_step = 0
        while range_step < 256:
            next_step = range_step + subnet_range
            if range_step < min(ip_range) < next_step:
                break
            range_step = next_step
        subnet_id = '{}.{}'.format(network_prefix, range_step)
        if sixteen:
            subnet_id = subnet_id + '.0'

        # Create a new subnet detail object and populate it with our details
        # Check if it already exists first though
        subnet = self.session.query(SubnetDetails). \
                                    filter(SubnetDetails.subnet_id==subnet_id)
        if subnet.count() == 0:
            subnet = SubnetDetails(subnet_id)
            subnet.cidr = cidr
            subnet.netmask = netmask
            subnet.number_hosts = no_hosts
            self.session.add(subnet)
            self.session.commit()
        else:
            subnet = subnet.first()

        return subnet


    def calculate_common_subnets(self):
        self.logger.debug('Begin calculating subnets...')
        common_ips = self.session.query(IPAddr).join(BreakinAttempts). \
            group_by(IPAddr.ip_addr).having(func.count(IPAddr.breakins)>=3).all()

        subnet24 = {}
        subnet16 = {}

        for index, ip in enumerate(common_ips):
            # Compare the item against all the other items in the list
            for index2, comparison_ip in enumerate(common_ips):
                if index != index2:  # don't compare the same address
                    result = self.compare_ip_strings(ip.ip_addr, comparison_ip.ip_addr)
                    if result == 16:
                        if self.get_first_16_bits(ip.ip_addr) not in subnet16.keys():
                            subnet16[self.get_first_16_bits(ip.ip_addr)] = [ip.ip_addr]
                        else:
                            subnet16[self.get_first_16_bits(ip.ip_addr)] += [ip.ip_addr]
                    elif result == 24:
                        if self.get_first_24_bits(ip.ip_addr) not in subnet24.keys():
                            subnet24[self.get_first_24_bits(ip.ip_addr)] = [ip.ip_addr]
                        else:
                            subnet24[self.get_first_24_bits(ip.ip_addr)] += [ip.ip_addr]
        self.logger.debug(subnet16)

        for network_prefix, ip_list in subnet24.items():
            if len(ip_list) >= 2:
                subnet = self.calculate_network_details(network_prefix, ip_list, twentyfour=True)
                for ip in ip_list:
                    ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr==ip).first()
                    ip_addr.subnet_id = subnet.id
                    self.session.add(ip_addr)
                    self.session.commit()

        for network_prefix, ip_list in subnet16.items():
            if len(ip_list) >= 2:
                subnet = self.calculate_network_details(network_prefix, ip_list, sixteen=True)
                for ip in ip_list:
                    ip_addr = self.session.query(IPAddr).filter(IPAddr.ip_addr==ip).first()
                    ip_addr.subnet_id = subnet.id
                    self.session.add(ip_addr)
                    self.session.commit()


    def parse(self):

        self.logger.info('Scrutiny, begin scrutinising.')
        last_month = datetime.now().replace(day=1) - timedelta(days=1)
        self.logger.info('Timezone setup...')
        displayed_time, time_offset, sys_tz = self.tz_setup()
        self.logger.info('Reading logs...')
        breakin_attempt, banned_ip = self.read_logs(LOG_DIR)
        unique_ips = set()
        for i in breakin_attempt.values():
            unique_ips.add(i[0])
        #ip_and_location = {}
        #print('Checking IP locations...')
        #for i in unique_ips:
        #    ip_and_location[i] = self.check_ip_location(i)
            # be a good citizen and only hit the site every two seconds
         #   time.sleep(2)

        self.logger.info('Inserting results into database...')
        self.insert_into_db(unique_ips, breakin_attempt, banned_ip)

        self.logger.info('Finished!')


    def setup_test_data(self):

        self.logger.info('Setup test data')
        last_month = datetime.now().replace(day=1) - timedelta(days=1)
        #print('Timezone setup...')
        #displayed_time, time_offset, sys_tz = self.tz_setup()
        self.create_db()
        populate_test_data(self.session)
        self.calculate_common_subnets()

        #self.delete_db()


