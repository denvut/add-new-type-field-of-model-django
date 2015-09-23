"""
$Id: models.py 64548 2015-09-02 13:18:11Z maxim $
"""
from django.db import models
from security.audit import log as audit_log
from lib import ValidationError
from lib.models import ModTimeModel, UpperCaseField
from django.db import IntegrityError, transaction
import itertools
from datetime import datetime
from django.utils.six import with_metaclass
class SystemConfig(ModTimeModel):

    #hardware_id = models.CharField(max_length = 64, unique = True)
    hardware_id = UpperCaseField(max_length = 64, unique=True)
    ip4_addr = models.GenericIPAddressField(null=True, protocol="ipv4", unique = True)
    ip4_prefix = models.IntegerField(null=True)
    ip4_gateway = models.GenericIPAddressField(null=True, protocol="ipv4")
    ip4_nameserver = models.GenericIPAddressField(null=True, protocol="ipv4")

    def properties(self):
        return { 'hardware_id'    : self.hardware_id.upper(),
                 'ip4_cidr'       : "%s/%s" % (self.ip4_addr, self.ip4_prefix),
                 'ip4_gateway'    : self.ip4_gateway,
                 'ip4_nameserver' : self.ip4_nameserver }

    @classmethod
    def existing_field(cls, hardware_id, id = None):
        objs = cls.objects.filter(hardware_id = hardware_id)
        if id is not None:
            objs = objs.exclude(pk=id)
        return "Hardware ID" if objs.exists() else "IPv4 address"

    @staticmethod
    def parse_cidr(ip4_cidr):
        return ip4_cidr.split('/') if ip4_cidr is not None else (None, None)

    @classmethod
    def create(cls, properties, user):
        ip4_addr, ip4_prefix = cls.parse_cidr(properties.get('ip4_cidr'))
        config = cls(hardware_id = properties['hardware_id'],
            ip4_addr = ip4_addr, ip4_prefix = ip4_prefix,
            ip4_gateway = properties.get('ip4_gateway'),
            ip4_nameserver = properties.get('ip4_nameserver'))
        sid = transaction.savepoint()
        try:
            config.save()
            transaction.savepoint_commit(sid)
        except IntegrityError:
            transaction.savepoint_rollback(sid)
            raise ValidationError("%s is already used" % cls.existing_field(properties['hardware_id']))

        audit_log(user, None, "Create ACS config %s:%s/%s" % (config.hardware_id, config.ip4_addr, config.ip4_prefix))
        return config

    def save(self, *args, **kwargs):
        sid = transaction.savepoint()
        try:
            super(SystemConfig, self).save(*args, **kwargs)
            transaction.savepoint_commit(sid)
        except IntegrityError:
            transaction.savepoint_rollback(sid)
            raise ValidationError("%s is already used" % self.existing_field(self.hardware_id, self.pk))

