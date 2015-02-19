"""
The database models used by Scrutiny.
"""

from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class IPAddr(Base):

    """
    This IP address table, holds the actual address and the location as found
    from the GeoIP service. Holds links to the other tables, BannedIPs, BreakinAttempts
    and SubnetDetails.
    """

    __tablename__ = 'ipaddr'
    id = Column(Integer, autoincrement=True, primary_key=True)
    ip_addr = Column(String(45), unique=True)
    city_name = Column(String(255))
    region = Column(String(255))
    country = Column(String(255))
    bans = relationship('BannedIPs', backref='ip', lazy='dynamic')
    breakins = relationship('BreakinAttempts', backref='ip', lazy='dynamic')
    subnet_id = Column(Integer, ForeignKey('subnetdetails.id'))

    def __init__(self, ip_addr):
        self.ip_addr = ip_addr

    def __repr__(self):
        return '<IP: {}>'.format(self.ip_addr)

    def print_location(self):

        """
        Prints the (rough) location of this IP address. Our GeoIP service
        does not return full details (such as city name) for all IP address,
        this will return as much information as we've been given in a nice format.
        """

        if self.city_name and self.region and self.country:
            return '{}, {}, {}'.format(self.city_name, self.region, self.country)
        elif self.region and self.country:
            return '{}, {}'.format(self.region, self.country)
        elif self.country:
            return '{}'.format(self.country)
        else:
            return '-'


class BannedIPs(Base):

    """
    The Banned IPs table, holds details about IP addresses that have been
    banned by fail2ban. Details are the date it was banned and a link back
    to the IP address table row for this IP address.
    """

    __tablename__ = 'bannedips'
    id = Column(Integer, autoincrement=True, primary_key=True)
    date = Column(DateTime)
    ipaddr = Column(Integer, ForeignKey('ipaddr.id'))

    def __repr__(self):
        return '<BannedIP: {}>'.format(self.date.strftime('%d-%m-%Y %H:%M:%S'))


class BreakinAttempts(Base):

    """
    The Breakin Attempts table. This table holds details of login attempts
    by an IP address, including the username they tried and the date/time.
    Has a link to the IP address table row for the IP address.
    """

    __tablename__ = 'breakinattempts'
    id = Column(Integer, autoincrement=True, primary_key=True)
    date = Column(DateTime)
    # Some programs accept only 8 character user names
    # The max for useradd seems to be 32 though, don't think
    # we'll see attempts with usernames longer than that though
    user = Column(String(32))
    ipaddr = Column(Integer, ForeignKey('ipaddr.id'))

    def __repr__(self):
        return '<BreakinAttempt: {} on {}>'.format(self.user,
                                                   self.date.strftime('%d-%m-%Y %H:%M:%S'))


class SubnetDetails(Base):

    """
    The Subnet Details table. This table holds details about common subnets
    as calculated by Scrutiny. The details included are the subnet id, the
    CIDR, the netmask and the number of hosts in the subnet. It also includes
    links back to the IP address table rows that hold IP addresses that are
    members of this subnet.
    """

    __tablename__ = 'subnetdetails'
    id = Column(Integer, autoincrement=True, primary_key=True)
    subnet_id = Column(String(15))
    cidr = Column(String(3))
    netmask = Column(String(15))
    number_hosts = Column(Integer)
    ipaddr = relationship('IPAddr', backref='subnetdetails')

    def __init__(self, subnet_id):
        self.subnet_id = subnet_id

    def __repr__(self):
        return '<Subnet:{}>'.format(self.subnet_id)
