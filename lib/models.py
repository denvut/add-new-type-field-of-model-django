"""
$Id: models.py 64462 2015-09-01 05:51:38Z stask $
"""

from django.db import models
from django.core.exceptions import ValidationError
import cPickle as pickle
from django.conf import settings
from lib.generic import first
from lib.watch import _get_serial_for_now
from lib.logging import debug, defaultLogger as logger, log_exc_trace
from lib.xml import find_invalid_xml_char
import binascii
import datetime, traceback
import random
import string
import json

class PickledField(models.TextField):
    """
PickledField - keep serialized instances of any python object that can be pickled
    """
    description = "Arbitrary python objects"
    __metaclass__ = models.SubfieldBase
    def __init__(self, **kwargs):
        super(self.__class__, self).__init__(serialize = False, **kwargs)

    def to_python(self, value):
        if isinstance(value, basestring):
            try:
                return pickle.loads(str(value))
            except:
                return value
        else:
            return value

    def get_prep_value(self, value):
        if value is None:
            return value
        try:
            return pickle.dumps(value)
        except pickle.PicklingError:
            return unicode(value)

def turnParentToChild(parent_instance, child_cls, **childfields):
    rv = child_cls(**childfields)
    for field in parent_instance._meta.fields:
        setattr(rv, field.attname, getattr(parent_instance, field.attname))

    return rv
# Following encrypted fields based on
# http://djangosnippets.org/snippets/1095 with following changes:
# - base64 encoding instead of just plain hex
# - size of char field is automatically adjusted during creation
# - form-related stuff removed.
# - unencrypted fields work.

class EncryptedString(str):
    """A subclass of string so it can be told whether a string is
       encrypted or not (if the object is an instance of this class
       then it must [well, should] be encrypted)."""
    pass

class BaseEncryptedField(models.Field):
    def __init__(self, *args, **kwargs):
        cipher = kwargs.pop('cipher', 'AES')
        imp = __import__('Crypto.Cipher', globals(), locals(), [cipher], -1)
        self.cipher = getattr(imp, cipher).new(settings.SECRET_KEY[:32])
        models.Field.__init__(self, *args, **kwargs)

    def to_python(self, value):
        if value is None:
            return value
        try:
            return unicode(self.cipher.decrypt(binascii.a2b_base64(str(value))).split('\0')[0], 'utf8')
        except:
            return value

    def db_type(self, connection):
        dct = self.__dict__.copy()
        try:
            dct['max_length'] = (dct['max_length'] + self.cipher.block_size) * 3 / 2
        except KeyError:
            pass
        return connection.creation.data_types[self.get_internal_type()] % dct

    def get_prep_value(self, value):
        value = value.encode('utf8') if value is not None else value
        if value is not None and not isinstance(value, EncryptedString):
            padding  = self.cipher.block_size - len(value) % self.cipher.block_size
            if padding and padding < self.cipher.block_size:
                value += "\0" + ''.join([random.choice(string.printable) for dummy in xrange(padding-1)])
            value = EncryptedString(binascii.b2a_base64(self.cipher.encrypt(value)))
        return value

class EncryptedTextField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return 'TextField'

class EncryptedCharField(BaseEncryptedField):
    __metaclass__ = models.SubfieldBase

    def get_internal_type(self):
        return "CharField"

class ConcurrentModException(Exception):
    pass

class ModTimeModel(models.Model):
    class Meta:
        abstract = True

    important_fields = None
    last_modified = models.DateTimeField(null = False, auto_now_add = True)
    serial = models.BigIntegerField(default=0)

    def __setattr__(self, name, value):
        test = self.important_fields is None and first(self._meta.fields, lambda f: name in (f.name, f.attname))
        test = test or self.important_fields is not None and name in self.important_fields
        test = test or name == "serial"
        test = test and name != 'last_modified'
        if test:
            modified = False
            try:
                modified = getattr(self, name) != value
            except (AttributeError, KeyError):
                pass

            if modified:
                ModTimeModel.set_modified(self)
        super(ModTimeModel, self).__setattr__(name, value)

    def set_modified(self):
        self.last_modified = datetime.datetime.now()
        self.__dict__['__modified'] = True

    def save(self, *args, **kwargs):
        old_serial = kwargs.pop('serial', None)
        if self.pk is not None and self.__dict__.get('__modified', False):
            new_serial = _get_serial_for_now()
            manager = self.__class__._default_manager
            if old_serial is not None:
                can_update = manager.filter(pk=self.pk, serial__lte = old_serial).update(serial=new_serial)
                if not can_update:
                    raise ConcurrentModException()
            super(ModTimeModel, self).__setattr__("serial", new_serial)
            del self.__dict__['__modified']
        super(ModTimeModel, self).save(*args, **kwargs)

    def properties(self):
        return { "last_modified": str(self.last_modified), "serial": self.serial }


class CloneableModel(models.Model):
    class Meta:
        abstract = True

    cloneable_content = []

    def clone(self, *args, **kwargs):
        ctargs = kwargs.copy()
        for field in self._meta.fields:
            if field.attname not in ctargs and field.name not in ctargs and not field.primary_key:
                    ctargs[field.name] = getattr(self, field.name)

        rv = self.__class__.objects.create(*args, **ctargs)

        all_names = set(rmodel.get_accessor_name() for rmodel in self._meta.get_all_related_objects())
        bad = [ k for k in self.cloneable_content if k not in all_names ]
        if bad:
            raise Exception("%s does not have any %s FKs" % (self.__class__,
                ", ".join(bad)))
        for rmodel in self._meta.get_all_related_objects():
            if rmodel.get_accessor_name() in self.cloneable_content:
                for robj in getattr(self, rmodel.get_accessor_name()).all():
                    robj.clone(**{ rmodel.field.name : rv})

        return rv
class NotArchivedManager(models.Manager):
    def get_query_set(self):
        return super(NotArchivedManager, self).get_query_set().filter(archived = False)

class XMLCharField(models.CharField):
    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        models.CharField.__init__(self, *args, **kwargs)

    def to_python(self, value):
        if value is None:
            return value

        pos, badchar = find_invalid_xml_char(value)
        if pos:
            raise ValidationError('bad character at position: {pos}, "{printable}" (code: {code})'.format(pos = pos, code = ord(badchar), printable = badchar))
        return value

class XMLTextField(models.TextField):
    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        models.TextField.__init__(self, *args, **kwargs)

    def to_python(self, value):
        if value is None:
            return value

        pos, badchar = find_invalid_xml_char(value)
        if pos:
            raise ValidationError('bad character at position: {pos}, "{printable}" (code: {code})'.format(pos = pos, code = ord(badchar), printable = badchar))
        return value

class TruncatingCharField(models.CharField):
    def get_prep_value(self, value):
        value = super(TruncatingCharField, self).get_prep_value(value)
        return value[:self.max_length] if value else value


class UpperCaseField(models.CharField):
    "Makes sure its content is always upper-case."
    __metaclass__ = models.SubfieldBase

    def to_python(self, value):
        return value.upper()

    def get_prep_value(self, value):
        return value.upper()



class JSONField(models.TextField):
    __metaclass__ = models.SubfieldBase

    def get_db_prep_value(self, value, connection, prepared=False):
        return json.dumps(value)

    def to_python(self, value):
        if not isinstance(value, basestring):
            return value
        try:
            return json.loads(value)
        except ValueError, e:
            return value

from south.modelsinspector import add_introspection_rules
add_introspection_rules([], [ "^lib\.models\.[a-zA-Z]+Field"])

class TemplateAttributeLookup(object):
    def __init__(self, func, instance=None):
        self.func = func
        self.instance = instance

    def __get__(self, instance, owner):
        return TemplateAttributeLookup(self.func, instance)

    def __getitem__(self, arg):
        return self.func(self.instance, arg)

    def __call__(self, arg=None):
        return self.func(self.instance, arg) if arg is not None else self

class SettingsBase(models.Model):
    class Meta:
        abstract = True

    BOOL_SETTINGS = ()
    VALUE_LIST_SETTINGS = ()

    value = models.CharField(max_length=2048)
    def get_value(self):
        if self.name in self.BOOL_SETTINGS:
            return self.value == "True"
        else:
            return self.value

    def __unicode__(self):
        return "{0.name} {0.value}".format(self)

    def properties(self):
        return {"name": self.name, "value": self.value}

    @classmethod
    def get(cls, name, **kwargs):
        if name not in cls.SETTINGS:
            raise Exception("Unknown {1} {0}".format(name, cls.__name__))

        try:
            obj = cls.objects.get(name=name, **kwargs)
        except cls.DoesNotExist:
            return cls.SETTINGS[name][1]

        return obj.get_value()

