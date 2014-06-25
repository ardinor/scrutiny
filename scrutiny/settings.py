import os

__version__ = 0.1
DEBUG = True

if DEBUG:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    DATABASE_URI = 'sqlite:///' + os.path.join(APP_DIR, 'app.db')
else:
    DATABASE_URI = ''


HOST_SERVER_NAME = 'defestri'
LOG_DIR = '/var/log/'
#LOG_DIR = 'F:/Temp/'

# Search string for the usual invalid user login attempts from /var/log/auth.log
# Jun 10 12:40:05 defestri sshd[11019]: Invalid user admin from 61.174.51.217
SEARCH_STRING = '(?P<log_date>^.*) {server} sshd.*Invalid user (?P<user>.*) from (?P<ip_add>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})'.format(server=HOST_SERVER_NAME)
# Search string for root login attempts from /var/log/auth.log
# Jun  8 04:31:10 defestri sshd[5013]: User root from 116.10.191.234 not allowed because none of user's groups are listed in AllowGroups
ROOT_NOT_ALLOWED_SEARCH_STRING = '(?P<log_date>^.*) {server} sshd.*User (?P<user>.*) from (?P<ip_add>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}) not allowed'.format(server=HOST_SERVER_NAME)
# Search string for fail2ban banning repeat offenders as logged in /var/log/fail2ban.log
# 2014-06-10 12:40:07,363 fail2ban.actions: WARNING [ssh] Ban 61.174.51.217
FAIL2BAN_SEARCH_STRING = '(?P<log_date>^.*) fail2ban.actions: WARNING \[ssh] Ban (?P<ip_add>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

API_URL = 'http://api.ipinfodb.com/v3/ip-city/'
API_KEY = ''
