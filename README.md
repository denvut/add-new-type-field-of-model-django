# add-new-type-field-of-model-django
Добавление своего типа поля (например: все заглавные  буквы ):
у меня есть файл где перечисленны все глобальные в рамках проекта  модели и типы полей библиотек
lib/models.py
туда добавляем свой новый тип поля:

class UpperCaseField(models.CharField):
    "Makes sure its content is always upper-case."
    __metaclass__ = models.SubfieldBase

    def to_python(self, value):
        return value.upper()

    def get_prep_value(self, value):
        return value.upper()

  так же если используется south 
  необходимо наличие 
  ниже  в модели если еще нет:

from south.modelsinspector import add_introspection_rules
add_introspection_rules([], [ "^lib\.models\.[a-zA-Z]+Field"])

и не забыть добавить в своей моделе:
from lib.models import ModTimeModel, UpperCaseField


это зарегистрирует новый тип поля при миграции 
в своей моделе вызываем просто: 

class SystemConfig(ModTimeModel):

    #hardware_id = models.CharField(max_length = 64, unique = True)
    hardware_id = UpperCaseField(max_length = 64, unique=True)
