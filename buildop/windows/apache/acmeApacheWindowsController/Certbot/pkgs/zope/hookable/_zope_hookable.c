/*############################################################################
 #
 #  Copyright (c) 2003 Zope Foundation and Contributors.
 #  All Rights Reserved.
 #
 #  This software is subject to the provisions of the Zope Public License,
 #  Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
 #  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
 #  WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 #  WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
 #  FOR A PARTICULAR PURPOSE.
 #
 ############################################################################*/

/* _zope_hookable.c

   Provide an efficient implementation for hookable objects

 */

#include "Python.h"
#include "structmember.h"

typedef struct {
    PyObject_HEAD
    PyObject *old;
    PyObject *implementation;
} hookable;

static int
hookable_init(hookable *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"implementation", NULL};
  PyObject *implementation;

  if (! PyArg_ParseTupleAndKeywords(args, kwds, "O:hookable", kwlist,
                                    &implementation))
    return -1;

  Py_INCREF(implementation);
  Py_INCREF(implementation);
  Py_XDECREF(self->old);
  self->old = implementation;
  Py_XDECREF(self->implementation);
  self->implementation = implementation;

  return 0;
}

static int
hookable_traverse(hookable *self, visitproc visit, void *arg)
{
  if (self->implementation != NULL && visit(self->implementation, arg) < 0)
    return -1;
  if (self->old != NULL
      && self->old != self->implementation
      && visit(self->old, arg) < 0
      )
    return -1;

  return 0;
}

static int
hookable_clear(hookable *self)
{
  Py_XDECREF(self->old);
  self->old = NULL;
  Py_XDECREF(self->implementation);
  self->implementation = NULL;
  return 0;
}


static void
hookable_dealloc(hookable *self)
{
  PyObject_GC_UnTrack((PyObject *)self);
  Py_XDECREF(self->old);
  Py_XDECREF(self->implementation);
  Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
hookable_sethook(hookable *self, PyObject *implementation)
{
  PyObject *old;

  old = self->implementation;
  Py_INCREF(implementation);
  self->implementation = implementation;

  if (old == NULL)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

  return old;
}

static PyObject *
hookable_reset(hookable *self)
{
  Py_XINCREF(self->old);
  Py_XDECREF(self->implementation);
  self->implementation = self->old;
  Py_INCREF(Py_None);
  return Py_None;
}

static struct PyMethodDef hookable_methods[] = {
  {"sethook",   (PyCFunction)hookable_sethook, METH_O,
   "Set the hook implementation for the hookable object"},
  {"reset", (PyCFunction)hookable_reset, METH_NOARGS,
   "Reset the hook to the original value"},
  {NULL,        NULL}       /* sentinel */
};


static PyObject *
hookable_call(hookable *self, PyObject *args, PyObject *kw)
{
  if (self->implementation != NULL)
    return PyObject_Call(self->implementation, args, kw);
  PyErr_SetString(PyExc_TypeError, "Hookable has no implementation");
  return NULL;
}


static PyObject *
hookable_getattro(hookable *self, PyObject *name)
{
    PyObject *result = NULL;
    const char *name_as_string;
    int maybe_special_name;

#if PY_MAJOR_VERSION < 3
    name_as_string = PyString_AsString(name);
#else
    name_as_string = PyUnicode_AsUTF8(name);
#endif

    if (name_as_string == NULL) {
        return NULL;
    }

    maybe_special_name = name_as_string[0] == '_' && name_as_string[1] == '_';

    if (maybe_special_name) {
        /* pass through __doc__ to the original implementation */
        if (strcmp("__doc__", name_as_string) == 0) {
            return PyObject_GetAttr(self->old, name);
        }
        /* synthesize __base__ and __dict__ if the original fails */
        if (strcmp("__bases__", name_as_string) == 0) {
            result = PyObject_GetAttr(self->old, name);
            if (result == NULL) {
                PyErr_Clear();
                result = PyTuple_New(0);
            }
            return result;
        }
        if (strcmp("__dict__", name_as_string) == 0) {
            result = PyObject_GetAttr(self->old, name);
            if (result == NULL) {
                PyErr_Clear();
                result = PyDict_New();
            }
            return result;
        }
    }

    return PyObject_GenericGetAttr((PyObject*)self, name);
}

static PyMemberDef hookable_members[] = {
  { "original", T_OBJECT_EX, offsetof(hookable, old), READONLY },
  { "implementation", T_OBJECT_EX, offsetof(hookable, implementation), READONLY },
  {NULL}    /* Sentinel */
};


static char Hookabletype__doc__[] =
"Callable objects that support being overridden"
;

static PyTypeObject hookabletype = {
    PyVarObject_HEAD_INIT(NULL, 0)
    /* tp_name           */ "zope.hookable."
                                "hookable",
    /* tp_basicsize      */ sizeof(hookable),
    /* tp_itemsize       */ 0,
    /* tp_dealloc        */ (destructor)&hookable_dealloc,
    /* tp_print          */ (printfunc)0,
    /* tp_getattr        */ (getattrfunc)0,
    /* tp_setattr        */ (setattrfunc)0,
    /* tp_compare        */ 0,
    /* tp_repr           */ (reprfunc)0,
    /* tp_as_number      */ 0,
    /* tp_as_sequence    */ 0,
    /* tp_as_mapping     */ 0,
    /* tp_hash           */ (hashfunc)0,
    /* tp_call           */ (ternaryfunc)hookable_call,
    /* tp_str            */ (reprfunc)0,
    /* tp_getattro       */ (getattrofunc)hookable_getattro,
    /* tp_setattro       */ (setattrofunc)0,
    /* tp_as_buffer      */ 0,
    /* tp_flags          */ Py_TPFLAGS_DEFAULT
                                | Py_TPFLAGS_BASETYPE
                                | Py_TPFLAGS_HAVE_GC,
    /* tp_doc            */ Hookabletype__doc__,
    /* tp_traverse       */ (traverseproc)hookable_traverse,
    /* tp_clear          */ (inquiry)hookable_clear,
    /* tp_richcompare    */ (richcmpfunc)0,
    /* tp_weaklistoffset */ (long)0,
    /* tp_iter           */ (getiterfunc)0,
    /* tp_iternext       */ (iternextfunc)0,
    /* tp_methods        */ hookable_methods,
    /* tp_members        */ hookable_members,
    /* tp_getset         */ 0,
    /* tp_base           */ 0,
    /* tp_dict           */ 0, /* internal use */
    /* tp_descr_get      */ (descrgetfunc)0,
    /* tp_descr_set      */ (descrsetfunc)0,
    /* tp_dictoffset     */ 0,
    /* tp_init           */ (initproc)hookable_init,
    /* tp_alloc          */ (allocfunc)0,
    /* tp_new            */ (newfunc)0 /*PyType_GenericNew*/,
    /* tp_free           */ 0/*PyObject_GC_Del*/,
};


#if PY_MAJOR_VERSION >= 3
  #define MOD_ERROR_VAL NULL
  #define MOD_SUCCESS_VAL(val) val
  #define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
      static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
      ob = PyModule_Create(&moduledef);
#else
  #define MOD_ERROR_VAL
  #define MOD_SUCCESS_VAL(val)
  #define MOD_INIT(name) void init##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
          ob = Py_InitModule3(name, methods, doc);
#endif

static struct PyMethodDef module_methods[] = {
    {NULL, NULL}
};

MOD_INIT(_zope_hookable)
{
  PyObject *m;

  MOD_DEF(m, "_zope_hookable",
    "Provide an efficient implementation for hookable objects",
    module_methods)

  if (m == NULL)
    return MOD_ERROR_VAL;

  hookabletype.tp_new = PyType_GenericNew;
  hookabletype.tp_free = PyObject_GC_Del;

  if (PyType_Ready(&hookabletype) < 0)
    return MOD_ERROR_VAL;

  if (PyModule_AddObject(m, "hookable", (PyObject *)&hookabletype) < 0)
    return MOD_ERROR_VAL;

  return MOD_SUCCESS_VAL(m);

}
