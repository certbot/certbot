# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from .base import *  # noqa

# don't use an unicode string
localeID = 'pt_BR'
dateSep = ['/']
usesMeridian = False
uses24 = True
decimal_mark = ','

Weekdays = [
    'segunda-feira', 'terça-feira', 'quarta-feira',
    'quinta-feira', 'sexta-feira', 'sábado', 'domingo',
]
shortWeekdays = [
    'seg', 'ter', 'qua', 'qui', 'sex', 'sáb', 'dom',
]
Months = [
    'janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho',
    'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'
]
shortMonths = [
    'jan', 'fev', 'mar', 'abr', 'mai', 'jun',
    'jul', 'ago', 'set', 'out', 'nov', 'dez'
]
dateFormats = {
    'full': "EEEE, d' de 'MMMM' de 'yyyy",
    'long': "d' de 'MMMM' de 'yyyy",
    'medium': "dd-MM-yy",
    'short': "dd/MM/yyyy",
}

timeFormats = {
    'full': "HH'H'mm' 'ss z",
    'long': "HH:mm:ss z",
    'medium': "HH:mm:ss",
    'short': "HH:mm",
}

dp_order = ['d', 'm', 'y']

units = {
    'seconds': ['segundo', 'seg', 's'],
    'minutes': ['minuto', 'min', 'm'],
    'days': ['dia', 'dias', 'd'],
    'months': ['mês', 'meses'],
}
