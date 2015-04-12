from datetime import timedelta, datetime

"""
Instead of parsing log files, perhaps it would be better to basically tail them,
subscribe to changes and when we see an entry that matches our regex, add it.
Or, scan through the log files on startup, then set the datetime of the last entry
we see as some 'last checked' value, then tail the logs.
"""


class LogFileReader():

    def __init__(self):
        pass


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


    def get_file_content(self, log_file):

        if os.path.splitext(log_file)[1] == '.gz':
            # Use zcat?
            with open(gzip.open(os.path.join(log_dir, log_file), 'r')) as f:
                file_content = f.read()  # comes out as bytes
            try:
                file_content = file_content.decode("utf-8") # convert to a string
            except AttributeError:
                pass # wasn't bytes, ignore
            content = file_content.split('\n')

            return content

        else:
            with open(os.path.join(log_dir, log_file), 'r') as f:
                content = f.read()

            return content


    def parse_sshd_content(self, content):

        matches = {}

        for line in content:
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
                    if log_date in matches:
                        while log_date in matches:
                            ns = log_date.second+1
                            if ns >= 60:
                                ns = 0
                            log_date = log_date.replace(second=ns)
                    matches[log_date] = (m.group('ip_add'), m.group('user'))

        return matches


    def read_sshd_logs(self):

        matches = {}

        for log_file is os.listdir(self.LOG_DIR):
            if 'auth.log' in log_file or 'secure' in log_file:
                modified_time = datetime.strptime(time.ctime(os.path.getmtime(
                                os.path.join(log_dir, log_file))), "%a %b %d %H:%M:%S %Y")
                if modified_time > self.last_run():
                    content = self.get_file_content(log_file)
                    file_matches = parse_sshd_content(content)



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
