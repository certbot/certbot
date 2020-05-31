from typing import Any
from . import packages
# from .packages import six
from . import fields

# six = packages.six
# b = six.b
RequestField = fields.RequestField

writer: Any

def choose_boundary(): ...
def iter_field_objects(fields): ...
def iter_fields(fields): ...
def encode_multipart_formdata(fields, boundary=...): ...
