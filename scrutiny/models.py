from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class IPAddr(Base):

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
        if self.city_name and self.region and self.country:
            return '{}, {}, {}'.format(self.city_name, self.region, self.country)
        elif self.region and self.country:
            return '{}, {}'.format(self.region, self.country)
        elif self.country:
            return '{}'.format(self.country)
        else:
            return '-'


class BannedIPs(Base):

    __tablename__ = 'bannedips'
    id = Column(Integer, autoincrement=True, primary_key=True)
    date = Column(DateTime)
    ipaddr = Column(Integer, ForeignKey('ipaddr.id'))

    def __repr__(self):
        return '<BannedIP: {}>'.format(self.date.strftime('%d-%m-%Y %H:%M:%S'))


class BreakinAttempts(Base):

    __tablename__ = 'breakinattempts'
    id = Column(Integer, autoincrement=True, primary_key=True)
    date = Column(DateTime)
    # Some programs accept only 8 character user names
    # The max for useradd seems to be 32 though, don't think
    # we'll see attempts with usernames longer than that though
    user = Column(String(32))
    ipaddr = Column(Integer, ForeignKey('ipaddr.id'))

    def __repr__(self):
        return '<BreakinAttempt: {} on {}>'.format(self.user, self.date.strftime('%d-%m-%Y %H:%M:%S'))


class SubnetDetails(Base):

    __tablename__ = 'subnetdetails'
    id = Column(Integer, autoincrement=True, primary_key=True)
    subnet_id = Column()
    cidr = Column()
    netmask = Column()
    number_hosts = Column()
    ipaddr = relationship('IPAddr', backref='subnetdetails')

    def __init__(self, subnet_id):
        self.subnet_id = subnet_id

    def __repr__(self):
        return '<Subnet:{}>'.format(self.subnet_id)
