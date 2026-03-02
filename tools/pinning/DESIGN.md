# Certbot dependency pinning

As described in the developer guide, we try to pin Certbot's dependencies to
well tested versions in almost all cases. Pinning Python dependencies across
different environments like this is actually quite tricky though and the files
under this directory make a somewhat reasonable, best effort approach to solve
this problem.

## Python packaging background

### Sdists and wheels

Python projects are most commonly distributed on [PyPI](https://pypi.org/) as
either a [source
distribution](https://packaging.python.org/glossary/#term-Source-Distribution-or-sdist)
or a [wheel](https://packaging.python.org/glossary/#term-Wheel). Wheels don't
present a problem for us pinning dependencies because they offer a well defined
format where the dependencies of a package can be easily parsed.

Source distributions or "sdists" are a problem though because they can contain
arbitrary Python code that must be run to determine the dependencies of the
package. This code could theoretically do anything, but it most commonly
inspects the environment it is running in and changes the project's
dependencies based the environment. As of writing this, we even do this in some
of Certbot's packages as you can see
[here](https://github.com/certbot/certbot/blob/8b610239bfcf7aac06f6e36d09a5abba3ba87047/certbot-dns-cloudflare/setup.py#L15-L27).
This is a problem because it means the environment an sdist was run in affects
the dependencies it declares making it difficult for us to determine Certbot's
dependencies for an arbitrary environment. Luckily, this is becoming less and
less of an issue with the increasing use of wheels, however, as of writing
this, some of Certbot's dependencies are still only available as sdists on some
platforms.

### Environment markers and pyproject.toml

Two other things have helped reduce the problems caused by sdists and are
relevant here. The first is the usage of [environment
markers](https://www.python.org/dev/peps/pep-0496/) which allows a package to
consistently declare its conditional dependencies with a static string
specifying the conditions where a dependency is required instead of dynamically
generating the list of required dependencies at runtime. This static string
keeps the package's declaration of its dependencies consistent across
environments.

The other relatively recent change in Python packaging is the adoption of
[pyproject.toml files](https://www.python.org/dev/peps/pep-0518/) which allows
sdists to define their packages using a static file instead of a setup.py
file, which has historically been the norm.
Using a static file instead of arbitrary Python code makes it
much easier for package declarations to be reliably interpreted. The
introduction of pyproject.toml also allows for the use of build systems other
than setuptools which becomes relevant in the next section of this doc.

## Our pinning system

### Overview

The files inside `tools/pinning` are used to generate Certbot's pinning files.
The files under `oldest` are used to generate the constraints file used for our
"oldest" tests while `current` is used to generate the constraints used
everywhere else. `common` includes shared files that are used for both sets of
pinnings.

Under `current` and `oldest`, there are two files as of writing this. One is a
pyproject.toml file for use with [Poetry](https://python-poetry.org/) while
the other is a script that can be run to regenerate pinnings. The
pyproject.toml file defines a Python package that depends on everything we want
to pin. This file largely just depends on our own local packages, however,
extra dependencies can be declared to further constrain package versions or to
declare additional dependencies.

The reason we use Poetry is that it is somewhat unique among Python packaging
tools in that when locking dependencies, it makes a best effort approach to do
this for all environments rather than just the current environment. This
includes recursively resolving dependencies declared through environment
markers that are not relevant for the current platform. It also includes
checking all wheels and sdists of a package for dependencies when picking a
specific version of a package from PyPI. You can see this in action through
the inclusion of dependencies like pywin32 which we only have a dependency on
for Windows.

### Potential problems

As of writing this, I'm aware of two potential problems with this pinning
system. The first is largely described earlier in the doc which is the problem
of sdists that use code to dynamically declare its dependencies. It's simply
not feasible to ensure this arbitrary Python code declares its dependencies in
the same way across all environments. Luckily, this is a largely a theoretical
problem and I'm aware of no issues with our current dependencies.

The second problem with this approach is that build dependencies are not
tracked and pinned. To be clear, normal runtime dependencies like those
declared in "install_requires" in setup.py files and even optional runtime
dependencies like those declared in "extras_require" in setup.py are managed
properly. The problem here is with dependencies needed at build time when
initially installing a Python project. These are usually specified in
"setup_requires" in setup.py or under "requires" in the "build-system" section
of pyproject.toml files.

Unfortunately, [tracking and pinning build dependencies seems to be a largely
unsolved problem in Python right
now](https://discuss.python.org/t/pinning-build-dependencies/8363). Our tooling
ensures that when installing build dependencies when using our pinning files
that versions from the pinning files are used (see
https://github.com/certbot/certbot/pull/8443 for more info about that), but I'm
not aware of any tool that automates the process of tracking and pinning down
build dependencies. For now, if we find any unpinned build dependencies, we can
declare a dependency on them in pyproject.toml. If a build dependency isn't
included in the constraints file, pip will use the latest version available on
PyPI.

## Theoretical future work

I think the system described above should work pretty well and I think it's
much better than the system we had before where how to update things like our
"oldest" pinnings was an open question. If we wanted to improve on this in the
future though, I think things to consider would be:

1. We could require that wheels are used for all of our dependencies. If a
   wheel is not available for one of our dependencies, we could try to work
   with upstream to change that or build it and host it locally for ourselves.
   (If we do the latter, how to pin build dependencies when building the wheel
   remains an open question.)
2. We could only really try to pin our dependencies for certain environments.
   This would be done by doing something like installing our packages in each
   environment we care about and saving the output of a command like `pip
   freeze`. With our use of snaps and Docker, this may be somewhat reasonable
   because we could base them all on a common system like Ubuntu LTS, however,
   it's not entirely trivial because we still have problems such as supporting
   multiple CPU architectures and pinning dependencies for Windows. Alternative
   development and test environments also wouldn't be fully supported.
3. We could help build better tooling that solves some of the problems with
   this approach or adopts it when it becomes available.
