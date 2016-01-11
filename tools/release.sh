#!/bin/bash -xe
# Release dev packages to PyPI

Usage() {
    echo Usage:
    echo "$0 [ --production ]"
    exit 1
}

if [ "`dirname $0`" != "tools" ] ; then
    echo Please run this script from the repo root
    exit 1
fi

CheckVersion() {
    # Args: <description of version type> <version number>
    if ! echo "$2" | grep -q -e '[0-9]\+.[0-9]\+.[0-9]\+' ; then
        echo "$1 doesn't look like 1.2.3"
        exit 1
    fi
}

if [ "$1" = "--production" ] ; then
    version="$2"
    CheckVersion Version "$version"
    echo Releasing production version "$version"...
    nextversion="$3"
    CheckVersion "Next version" "$nextversion"
    RELEASE_BRANCH="candidate-$version"
else
    version=`grep "__version__" letsencrypt/__init__.py | cut -d\' -f2 | sed s/\.dev0//`
    version="$version.dev$(date +%Y%m%d)1"
    RELEASE_BRANCH="dev-release"
    echo Releasing developer version "$version"...
fi

if [ "$RELEASE_OPENSSL_KEY" = "" ] ; then
    RELEASE_OPENSSL_KEY="`realpath \`dirname $0\``/eff-pubkey.pem"
fi
RELEASE_GPG_KEY=${RELEASE_GPG_KEY:-A2CFB51FA275A7286234E7B24D17C995CD9775F2}
# Needed to fix problems with git signatures and pinentry
export GPG_TTY=$(tty)

# port for a local Python Package Index (used in testing)
PORT=${PORT:-1234}

# subpackages to be released
SUBPKGS=${SUBPKGS:-"acme letsencrypt-apache letsencrypt-nginx letshelp-letsencrypt"}
subpkgs_modules="$(echo $SUBPKGS | sed s/-/_/g)"
# letsencrypt_compatibility_test is not packaged because:
# - it is not meant to be used by anyone else than Let's Encrypt devs
# - it causes problems when running nosetests - the latter tries to
#   run everything that matches test*, while there are no unittests
#   there

tag="v$version"
mv "dist.$version" "dist.$version.$(date +%s).bak" || true
git tag --delete "$tag" || true

tmpvenv=$(mktemp -d)
virtualenv --no-site-packages -p python2 $tmpvenv
. $tmpvenv/bin/activate
# update setuptools/pip just like in other places in the repo
pip install -U setuptools
pip install -U pip  # latest pip => no --pre for dev releases
pip install -U wheel  # setup.py bdist_wheel

# newer versions of virtualenv inherit setuptools/pip/wheel versions
# from current env when creating a child env
pip install -U virtualenv

root_without_le="$version.$$"
root="./releases/le.$root_without_le"

echo "Cloning into fresh copy at $root"  # clean repo = no artificats
git clone . $root
git rev-parse HEAD
cd $root
if [ "$RELEASE_BRANCH" != "candidate-$version" ] ; then
    git branch -f "$RELEASE_BRANCH"
fi
git checkout "$RELEASE_BRANCH"

# ensure we have the latest built version of leauto
letsencrypt-auto-source/build.py

# and that it's signed correctly
if ! openssl dgst -sha256 -verify $RELEASE_OPENSSL_KEY -signature \
        letsencrypt-auto-source/letsencrypt-auto.sig \
        letsencrypt-auto-source/letsencrypt-auto            ; then
   echo Failed letsencrypt-auto signature check on "$RELEASE_BRANCH"
   echo please fix that and re-run
   exit 1
else
    echo Signature check on letsencrypt-auto successful
fi


SetVersion() {
    ver="$1"
    for pkg_dir in $SUBPKGS
    do
      sed -i "s/^version.*/version = '$ver'/" $pkg_dir/setup.py
    done
    sed -i "s/^__version.*/__version__ = '$ver'/" letsencrypt/__init__.py

    git add -p letsencrypt $SUBPKGS # interactive user input
}
SetVersion "$version"
git commit --gpg-sign="$RELEASE_GPG_KEY" -m "Release $version"
git tag --local-user "$RELEASE_GPG_KEY" \
    --sign --message "Release $version" "$tag"

echo "Preparing sdists and wheels"
for pkg_dir in . $SUBPKGS
do
  cd $pkg_dir

  python setup.py clean
  rm -rf build dist
  python setup.py sdist
  python setup.py bdist_wheel

  echo "Signing ($pkg_dir)"
  for x in dist/*.tar.gz dist/*.whl
  do
      gpg -u "$RELEASE_GPG_KEY" --detach-sign --armor --sign $x
  done

  cd -
done


mkdir "dist.$version"
mv dist "dist.$version/letsencrypt"
for pkg_dir in $SUBPKGS
do
  mv $pkg_dir/dist "dist.$version/$pkg_dir/"
done

echo "Testing packages"
cd "dist.$version"
# start local PyPI
python -m SimpleHTTPServer $PORT &
# cd .. is NOT done on purpose: we make sure that all subpackages are
# installed from local PyPI rather than current directory (repo root)
virtualenv --no-site-packages ../venv
. ../venv/bin/activate
pip install -U setuptools
pip install -U pip
# Now, use our local PyPI
pip install \
  --extra-index-url http://localhost:$PORT \
  letsencrypt $SUBPKGS
# stop local PyPI
kill $!
cd ~-

# freeze before installing anything else, so that we know end-user KGS
# make sure "twine upload" doesn't catch "kgs"
if [ -d ../kgs ] ; then
    echo Deleting old kgs...
    rm -rf ../kgs
fi
mkdir ../kgs
kgs="../kgs/$version"
pip freeze | tee $kgs
pip install nose
for module in letsencrypt $subpkgs_modules ; do
    echo testing $module
    nosetests $module
done
deactivate

cd ..
echo Now in $PWD
name=${root_without_le%.*}
ext="${root_without_le##*.}"
rev="$(git rev-parse --short HEAD)"
echo tar cJvf $name.$rev.tar.xz $name.$rev
echo gpg -U $RELEASE_GPG_KEY --detach-sign --armor $name.$rev.tar.xz
cd ~-

echo "New root: $root"
echo "KGS is at $root/kgs"
echo "Test commands (in the letstest repo):"
echo 'python multitester.py targets.yaml $AWS_KEY $USERNAME scripts/test_leauto_upgrades.sh --alt_pip $YOUR_PIP_REPO --branch public-beta'
echo 'python multitester.py  targets.yaml $AWK_KEY $USERNAME scripts/test_letsencrypt_auto_certonly_standalone.sh --branch candidate-0.1.1'
echo 'python multitester.py --saveinstances targets.yaml $AWS_KEY $USERNAME scripts/test_apache2.sh'
echo "In order to upload packages run the following command:"
echo twine upload "$root/dist.$version/*/*"

if [ "$RELEASE_BRANCH" = candidate-"$version" ] ; then
    SetVersion "$nextversion".dev0
    git diff
    git commit -m "Bump version to $nextversion"
fi
