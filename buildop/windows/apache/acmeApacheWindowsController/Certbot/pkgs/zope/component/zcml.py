##############################################################################
#
# Copyright (c) 2005 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Component Architecture configuration handlers
"""
from zope.configuration.exceptions import ConfigurationError
from zope.configuration.fields import Bool
from zope.configuration.fields import GlobalInterface
from zope.configuration.fields import GlobalObject
from zope.configuration.fields import PythonIdentifier
from zope.configuration.fields import Tokens
from zope.i18nmessageid import MessageFactory
from zope.interface import Interface
from zope.interface import implementedBy
from zope.interface import providedBy
from zope.schema import TextLine

from zope.component._api import getSiteManager
from zope.component._declaration import adaptedBy, getName
from zope.component.interface import provideInterface

try:
    from zope.security.zcml import Permission
except ImportError: #pragma NO COVER
    def _no_security(*args, **kw):
        raise ConfigurationError("security proxied components are not "
            "supported because zope.security is not available")
    _checker = proxify = protectedFactory = security =_no_security
    Permission = TextLine
else:
    from zope.component.security import _checker
    from zope.component.security import proxify
    from zope.component.security import protectedFactory
    from zope.component.security import securityAdapterFactory

_ = MessageFactory('zope')

class ComponentConfigurationError(ValueError, ConfigurationError):
    pass

def handler(methodName, *args, **kwargs):
    method = getattr(getSiteManager(), methodName)
    method(*args, **kwargs)

class IBasicComponentInformation(Interface):

    component = GlobalObject(
        title=_("Component to use"),
        description=_("Python name of the implementation object.  This"
                      " must identify an object in a module using the"
                      " full dotted name.  If specified, the"
                      " ``factory`` field must be left blank."),
        required=False,
        )

    permission = Permission(
        title=_("Permission"),
        description=_("Permission required to use this component."),
        required=False,
        )

    factory = GlobalObject(
        title=_("Factory"),
        description=_("Python name of a factory which can create the"
                      " implementation object.  This must identify an"
                      " object in a module using the full dotted name."
                      " If specified, the ``component`` field must"
                      " be left blank."),
        required=False,
        )

class IAdapterDirective(Interface):
    """
    Register an adapter
    """

    factory = Tokens(
        title=_("Adapter factory/factories"),
        description=_("A list of factories (usually just one) that create"
                      " the adapter instance."),
        required=True,
        value_type=GlobalObject()
        )

    provides = GlobalInterface(
        title=_("Interface the component provides"),
        description=_("This attribute specifies the interface the adapter"
                      " instance must provide."),
        required=False,
        )

    for_ = Tokens(
        title=_("Specifications to be adapted"),
        description=_("This should be a list of interfaces or classes"),
        required=False,
        value_type=GlobalObject(
          missing_value=object(),
          ),
        )

    permission = Permission(
        title=_("Permission"),
        description=_("This adapter is only available, if the principal"
                      " has this permission."),
        required=False,
        )

    name = TextLine(
        title=_("Name"),
        description=_("Adapters can have names.\n\n"
                      "This attribute allows you to specify the name for"
                      " this adapter."),
        required=False,
        )

    trusted = Bool(
        title=_("Trusted"),
        description=_("""Make the adapter a trusted adapter

        Trusted adapters have unfettered access to the objects they
        adapt.  If asked to adapt security-proxied objects, then,
        rather than getting an unproxied adapter of security-proxied
        objects, you get a security-proxied adapter of unproxied
        objects.
        """),
        required=False,
        default=False,
        )

    locate = Bool(
        title=_("Locate"),
        description=_("""Make the adapter a locatable adapter

        Located adapter should be used if a non-public permission
        is used.
        """),
        required=False,
        default=False,
        )

def _rolledUpFactory(factories):
    # This has to be named 'factory', aparently, so as not to confuse
    # apidoc :(
    def factory(ob):
        for f in factories:
            ob = f(ob)
        return ob
    # Store the original factory for documentation
    factory.factory = factories[0]
    return factory

def adapter(_context, factory, provides=None, for_=None, permission=None,
            name='', trusted=False, locate=False):

    if for_ is None:
        if len(factory) == 1:
            for_ = adaptedBy(factory[0])

        if for_ is None:
            raise TypeError("No for attribute was provided and can't "
                            "determine what the factory adapts.")

    for_ = tuple(for_)

    if provides is None:
        if len(factory) == 1:
            p = list(implementedBy(factory[0]))
            if len(p) == 1:
                provides = p[0]

        if provides is None:
            raise TypeError("Missing 'provides' attribute")

    if name == '':
        if len(factory) == 1:
            name = getName(factory[0])

    # Generate a single factory from multiple factories:
    factories = factory
    if len(factories) == 1:
        factory = factories[0]
    elif len(factories) < 1:
        raise ComponentConfigurationError("No factory specified")
    elif len(factories) > 1 and len(for_) != 1:
        raise ComponentConfigurationError(
            "Can't use multiple factories and multiple for")
    else:
        factory = _rolledUpFactory(factories)

    if permission is not None:
        factory = protectedFactory(factory, provides, permission)

    # invoke custom adapter factories
    if locate or permission is not None or trusted:
        factory = securityAdapterFactory(factory, permission, locate, trusted)

    _context.action(
        discriminator = ('adapter', for_, provides, name),
        callable = handler,
        args = ('registerAdapter',
                factory, for_, provides, name, _context.info),
        )
    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = ('', provides)
               )
    if for_:
        for iface in for_:
            if iface is not None:
                _context.action(
                    discriminator = None,
                    callable = provideInterface,
                    args = ('', iface)
                    )

class ISubscriberDirective(Interface):
    """
    Register a subscriber
    """

    factory = GlobalObject(
        title=_("Subscriber factory"),
        description=_("A factory used to create the subscriber instance."),
        required=False,
        )

    handler = GlobalObject(
        title=_("Handler"),
        description=_("A callable object that handles events."),
        required=False,
        )

    provides = GlobalInterface(
        title=_("Interface the component provides"),
        description=_("This attribute specifies the interface the adapter"
                      " instance must provide."),
        required=False,
        )

    for_ = Tokens(
        title=_("Interfaces or classes that this subscriber depends on"),
        description=_("This should be a list of interfaces or classes"),
        required=False,
        value_type=GlobalObject(
          missing_value = object(),
          ),
        )

    permission = Permission(
        title=_("Permission"),
        description=_("This subscriber is only available, if the"
                      " principal has this permission."),
        required=False,
        )

    trusted = Bool(
        title=_("Trusted"),
        description=_("""Make the subscriber a trusted subscriber

        Trusted subscribers have unfettered access to the objects they
        adapt.  If asked to adapt security-proxied objects, then,
        rather than getting an unproxied subscriber of security-proxied
        objects, you get a security-proxied subscriber of unproxied
        objects.
        """),
        required=False,
        default=False,
        )

    locate = Bool(
        title=_("Locate"),
        description=_("""Make the subscriber a locatable subscriber

        Located subscribers should be used if a non-public permission
        is used.
        """),
        required=False,
        default=False,
        )

_handler = handler
def subscriber(_context, for_=None, factory=None, handler=None, provides=None,
               permission=None, trusted=False, locate=False):
    if factory is None:
        if handler is None:
            raise TypeError("No factory or handler provided")
        if provides is not None:
            raise TypeError("Cannot use handler with provides")
        factory = handler
    else:
        if handler is not None:
            raise TypeError("Cannot use handler with factory")
        if provides is None:
            raise TypeError(
                "You must specify a provided interface when registering "
                "a factory")

    if for_ is None:
        for_ = adaptedBy(factory)
        if for_ is None:
            raise TypeError("No for attribute was provided and can't "
                            "determine what the factory (or handler) adapts.")

    if permission is not None:
        factory = protectedFactory(factory, provides, permission)

    for_ = tuple(for_)

    # invoke custom adapter factories
    if locate or permission is not None or trusted:
        factory = securityAdapterFactory(factory, permission, locate, trusted)

    if handler is not None:
        _context.action(
            discriminator = None,
            callable = _handler,
            args = ('registerHandler',
                    handler, for_, u'', _context.info),
            )
    else:
        _context.action(
            discriminator = None,
            callable = _handler,
            args = ('registerSubscriptionAdapter',
                    factory, for_, provides, u'', _context.info),
            )

    if provides is not None:
        _context.action(
            discriminator = None,
            callable = provideInterface,
            args = ('', provides)
            )

    # For each interface, state that the adapter provides that interface.
    for iface in for_:
        if iface is not None:
            _context.action(
                discriminator = None,
                callable = provideInterface,
                args = ('', iface)
                )

class IUtilityDirective(IBasicComponentInformation):
    """Register a utility."""

    provides = GlobalInterface(
        title=_("Provided interface"),
        description=_("Interface provided by the utility."),
        required=False,
        )

    name = TextLine(
        title=_("Name"),
        description=_("Name of the registration.  This is used by"
                      " application code when locating a utility."),
        required=False,
        )

def utility(_context, provides=None, component=None, factory=None,
            permission=None, name=''):
    if factory and component:
        raise TypeError("Can't specify factory and component.")

    if provides is None:
        if factory:
            provides = list(implementedBy(factory))
        else:
            provides = list(providedBy(component))
        if len(provides) == 1:
            provides = provides[0]
        else:
            raise TypeError("Missing 'provides' attribute")

    if name == '':
        if factory:
            name = getName(factory)
        else:
            name = getName(component)

    if permission is not None:
        component = proxify(component, provides=provides, permission=permission)

    _context.action(
        discriminator = ('utility', provides, name),
        callable = handler,
        args = ('registerUtility', component, provides, name, _context.info),
        kw = dict(factory=factory),
        )
    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = ('', provides),
        )

class IInterfaceDirective(Interface):
    """
    Define an interface
    """

    interface = GlobalInterface(
        title=_("Interface"),
        required=True,
        )

    type = GlobalInterface(
        title=_("Interface type"),
        required=False,
        )

    name = TextLine(
        title=_("Name"),
        required=False,
        )

def interface(_context, interface, type=None, name=''):
    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = (name, interface, type)
        )

class IBasicViewInformation(Interface):
    """This is the basic information for all views."""

    for_ = Tokens(
        title=_("Specifications of the objects to be viewed"),
        description=_("""This should be a list of interfaces or classes
        """),
        required=True,
        value_type=GlobalObject(
          missing_value=object(),
          ),
        )

    permission = Permission(
        title=_("Permission"),
        description=_("The permission needed to use the view."),
        required=False,
        )

    class_ = GlobalObject(
        title=_("Class"),
        description=_("A class that provides attributes used by the view."),
        required=False,
        )

    allowed_interface = Tokens(
        title=_("Interface that is also allowed if user has permission."),
        description=_("""
        By default, 'permission' only applies to viewing the view and
        any possible sub views. By specifying this attribute, you can
        make the permission also apply to everything described in the
        supplied interface.

        Multiple interfaces can be provided, separated by
        whitespace."""),
        required=False,
        value_type=GlobalInterface(),
        )

    allowed_attributes = Tokens(
        title=_("View attributes that are also allowed if the user"
                " has permission."),
        description=_("""
        By default, 'permission' only applies to viewing the view and
        any possible sub views. By specifying 'allowed_attributes',
        you can make the permission also apply to the extra attributes
        on the view object."""),
        required=False,
        value_type=PythonIdentifier(),
        )

class IBasicResourceInformation(Interface):
    """
    Basic information for resources
    """

    name = TextLine(
        title=_("The name of the resource."),
        description=_("The name shows up in URLs/paths. For example 'foo'."),
        required=True,
        default=u'',
        )

    provides = GlobalInterface(
        title=_("The interface this component provides."),
        description=_("""
        A view can provide an interface.  This would be used for
        views that support other views."""),
        required=False,
        default=Interface,
        )

    type = GlobalInterface(
        title=_("Request type"),
        required=True
        )


class IViewDirective(IBasicViewInformation, IBasicResourceInformation):
    """Register a view for a component"""

    factory = Tokens(
        title=_("Factory"),
        required=False,
        value_type=GlobalObject(),
        )

def view(_context, factory, type, name, for_,
         permission=None,
         allowed_interface=None,
         allowed_attributes=None,
         provides=Interface,
        ):

    if ((allowed_attributes or allowed_interface)
        and (not permission)):
        raise ComponentConfigurationError(
            "'permission' required with 'allowed_interface' or "
            "'allowed_attributes'")

    if permission is not None:

        checker = _checker(_context, permission,
                           allowed_interface, allowed_attributes)

        class ProxyView(object):
            """Class to create simple proxy views."""

            def __init__(self, factory, checker):
                self.factory = factory
                self.checker = checker

            def __call__(self, *objects):
                return proxify(self.factory(*objects), self.checker)

        factory[-1] = ProxyView(factory[-1], checker)


    if not for_:
        raise ComponentConfigurationError("No for interfaces specified");
    for_ = tuple(for_)

    # Generate a single factory from multiple factories:
    factories = factory
    if len(factories) == 1:
        factory = factories[0]
    elif len(factories) < 1:
        raise ComponentConfigurationError("No view factory specified")
    elif len(factories) > 1 and len(for_) > 1:
        raise ComponentConfigurationError(
            "Can't use multiple factories and multiple for")
    else:
        def factory(ob, request):
            for f in factories[:-1]:
                ob = f(ob)
            return factories[-1](ob, request)
        factory.factory = factories[0]

    for_ = for_ + (type,)

    _context.action(
        discriminator = ('view', for_, name, provides),
        callable = handler,
        args = ('registerAdapter',
                factory, for_, provides, name, _context.info),
        )

    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = ('', provides)
        )

    if for_ is not None:
        for iface in for_:
            if iface is not None:
                _context.action(
                    discriminator = None,
                    callable = provideInterface,
                    args = ('', iface)
                    )


class IResourceDirective(IBasicComponentInformation,
                         IBasicResourceInformation):
    """Register a resource"""

    allowed_interface = Tokens(
        title=_("Interface that is also allowed if user has permission."),
        required=False,
        value_type=GlobalInterface(),
        )

    allowed_attributes = Tokens(
        title=_("View attributes that are also allowed if user"
                " has permission."),
        required=False,
        value_type=PythonIdentifier(),
        )

def resource(_context, factory, type, name,
             permission=None,
             allowed_interface=None, allowed_attributes=None,
             provides=Interface):

    if ((allowed_attributes or allowed_interface)
        and (not permission)):
        raise ComponentConfigurationError(
            "Must use name attribute with allowed_interface or "
            "allowed_attributes"
            )

    if permission is not None:

        checker = _checker(_context, permission,
                           allowed_interface, allowed_attributes)

        def proxyResource(request, factory=factory, checker=checker):
            return proxify(factory(request), checker)
        proxyResource.factory = factory

        factory = proxyResource

    _context.action(
        discriminator = ('resource', name, type, provides),
        callable = handler,
        args = ('registerAdapter',
                factory, (type,), provides, name, _context.info))
    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = ('', type))
    _context.action(
        discriminator = None,
        callable = provideInterface,
        args = ('', provides))
