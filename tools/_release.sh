#!/bin/bash -xe
# Release packages to PyPI

if [ "$RELEASE_DIR" = "" ]; then
    echo Please run this script through the tools/release.sh wrapper script or set the environment
    echo variable RELEASE_DIR to the directory where the release should be built.
    exit 1
fi

version="$1"
echo Releasing production version "$version"...
nextversion="$2"
RELEASE_BRANCH="candidate-$version"

if [ "$RELEASE_OPENSSL_PUBKEY" = "" ] ; then
    RELEASE_OPENSSL_PUBKEY="`realpath \`dirname $0\``/eff-pubkey.pem"
fi
RELEASE_GPG_KEY=${RELEASE_GPG_KEY:-A2CFB51FA275A7286234E7B24D17C995CD9775F2}
# Needed to fix problems with git signatures and pinentry
export GPG_TTY=$(tty)

# port for a local Python Package Index (used in testing)
PORT=${PORT:-1234}

# subpackages to be released (the way developers think about them)
SUBPKGS_IN_AUTO_NO_CERTBOT="acme certbot-apache certbot-nginx"
SUBPKGS_NOT_IN_AUTO="certbot-dns-cloudflare certbot-dns-cloudxns certbot-dns-digitalocean certbot-dns-dnsimple certbot-dns-dnsmadeeasy certbot-dns-gehirn certbot-dns-google certbot-dns-linode certbot-dns-luadns certbot-dns-nsone certbot-dns-ovh certbot-dns-rfc2136 certbot-dns-route53 certbot-dns-sakuracloud"

# subpackages to be released (the way the script thinks about them)
SUBPKGS_IN_AUTO="certbot $SUBPKGS_IN_AUTO_NO_CERTBOT"
SUBPKGS_NO_CERTBOT="$SUBPKGS_IN_AUTO_NO_CERTBOT $SUBPKGS_NOT_IN_AUTO"
SUBPKGS="$SUBPKGS_IN_AUTO $SUBPKGS_NOT_IN_AUTO"
subpkgs_modules="$(echo $SUBPKGS | sed s/-/_/g)"
# certbot_compatibility_test is not packaged because:
# - it is not meant to be used by anyone else than Certbot devs
# - it causes problems when running pytest - the latter tries to
#   run everything that matches test*, while there are no unittests
#   there

tag="v$version"
mv "dist.$version" "dist.$version.$(date +%s).bak" || true
git tag --delete "$tag" || true

tmpvenv=$(mktemp -d)
VIRTUALENV_NO_DOWNLOAD=1 virtualenv --no-site-packages -p python2 $tmpvenv
. $tmpvenv/bin/activate
# update setuptools/pip just like in other places in the repo
pip install -U setuptools
pip install -U pip  # latest pip => no --pre for dev releases
pip install -U wheel  # setup.py bdist_wheel

# newer versions of virtualenv inherit setuptools/pip/wheel versions
# from current env when creating a child env
pip install -U virtualenv

root_without_le="$version.$$"
root="$RELEASE_DIR/le.$root_without_le"

echo "Cloning into fresh copy at $root"  # clean repo = no artifacts
git clone . $root
git rev-parse HEAD
cd $root
if [ "$RELEASE_BRANCH" != "candidate-$version" ] ; then
    git branch -f "$RELEASE_BRANCH"
fi
git checkout "$RELEASE_BRANCH"

# Update changelog
sed -i "s/master/$(date +'%Y-%m-%d')/" CHANGELOG.md
git add CHANGELOG.md
git diff --cached
git commit -m "Update changelog for $version release"

for pkg_dir in $SUBPKGS_NO_CERTBOT certbot-compatibility-test .
do
  sed -i 's/\.dev0//' "$pkg_dir/setup.py"
  git add "$pkg_dir/setup.py"

  if [ -f "$pkg_dir/local-oldest-requirements.txt" ]; then
    sed -i "s/-e acme\[dev\]/acme[dev]==$version/" "$pkg_dir/local-oldest-requirements.txt"
    sed -i "s/-e acme/acme[dev]==$version/" "$pkg_dir/local-oldest-requirements.txt"
    sed -i "s/-e \.\[dev\]/certbot[dev]==$version/" "$pkg_dir/local-oldest-requirements.txt"
    sed -i "s/-e \./certbot[dev]==$version/" "$pkg_dir/local-oldest-requirements.txt"
    git add "$pkg_dir/local-oldest-requirements.txt"
  fi
done

SetVersion() {
    ver="$1"
    # bumping Certbot's version number is done differently
    for pkg_dir in $SUBPKGS_NO_CERTBOT certbot-compatibility-test
    do
      setup_file="$pkg_dir/setup.py"
      if [ $(grep -c '^version' "$setup_file") != 1 ]; then
        echo "Unexpected count of version variables in $setup_file"
        exit 1
      fi
      sed -i "s/^version.*/version = '$ver'/" $pkg_dir/setup.py
    done
    init_file="certbot/__init__.py"
    if [ $(grep -c '^__version' "$init_file") != 1 ]; then
      echo "Unexpected count of __version variables in $init_file"
      exit 1
    fi
    sed -i "s/^__version.*/__version__ = '$ver'/" "$init_file"

    git add $SUBPKGS certbot-compatibility-test
}

SetVersion "$version"

# Unset CERTBOT_OLDEST to prevent wheels from being built improperly due to
# conditionals like the one found in certbot-dns-dnsimple's setup.py file.
unset CERTBOT_OLDEST
echo "Preparing sdists and wheels"
for pkg_dir in . $SUBPKGS_NO_CERTBOT
do
  cd $pkg_dir

  python setup.py clean
  rm -rf build dist
  python setup.py sdist
  python setup.py bdist_wheel

  echo "Signing ($pkg_dir)"
  for x in dist/*.tar.gz dist/*.whl
  do
      gpg2 -u "$RELEASE_GPG_KEY" --detach-sign --armor --sign --digest-algo sha256 $x
  done

  cd -
done


mkdir "dist.$version"
mv dist "dist.$version/certbot"
for pkg_dir in $SUBPKGS_NO_CERTBOT
do
  mv $pkg_dir/dist "dist.$version/$pkg_dir/"
done

echo "Testing packages"
cd "dist.$version"
# start local PyPI
python -m SimpleHTTPServer $PORT &
# cd .. is NOT done on purpose: we make sure that all subpackages are
# installed from local PyPI rather than current directory (repo root)
VIRTUALENV_NO_DOWNLOAD=1 virtualenv --no-site-packages ../venv
. ../venv/bin/activate
pip install -U setuptools
pip install -U pip
# Now, use our local PyPI. Disable cache so we get the correct KGS even if we
# (or our dependencies) have conditional dependencies implemented with if
# statements in setup.py and we have cached wheels lying around that would
# cause those ifs to not be evaluated.
python ../tools/pip_install.py \
  --no-cache-dir \
  --extra-index-url http://localhost:$PORT \
  $SUBPKGS
# stop local PyPI
kill $!
cd ~-

# get a snapshot of the CLI help for the docs
# We set CERTBOT_DOCS to use dummy values in example user-agent string.
CERTBOT_DOCS=1 certbot --help all > docs/cli-help.txt
jws --help > acme/docs/jws-help.txt

cd ..
# freeze before installing anything else, so that we know end-user KGS
# make sure "twine upload" doesn't catch "kgs"
if [ -d kgs ] ; then
    echo Deleting old kgs...
    rm -rf kgs
fi
mkdir kgs
kgs="kgs/$version"
pip freeze | tee $kgs
python ../tools/pip_install.py pytest
for module in $subpkgs_modules ; do
    echo testing $module
    # use an empty configuration file rather than the one in the repo root
    pytest -c <(echo '') --pyargs $module
done
cd ~-

# pin pip hashes of the things we just built
for pkg in $SUBPKGS_IN_AUTO ; do
    echo $pkg==$version \\
    pip hash dist."$version/$pkg"/*.{whl,gz} | grep "^--hash" | python2 -c 'from sys import stdin; input = stdin.read(); print "   ", input.replace("\n--hash", " \\\n    --hash"),'
done > letsencrypt-auto-source/pieces/certbot-requirements.txt
deactivate

# there should be one requirement specifier and two hashes for each subpackage
expected_count=$(expr $(echo $SUBPKGS_IN_AUTO | wc -w) \* 3)
if ! wc -l letsencrypt-auto-source/pieces/certbot-requirements.txt | grep -qE "^\s*$expected_count " ; then
    echo Unexpected pip hash output
    exit 1
fi

# ensure we have the latest built version of leauto
letsencrypt-auto-source/build.py

# and that it's signed correctly
tools/offline-sigrequest.sh || true
while ! openssl dgst -sha256 -verify $RELEASE_OPENSSL_PUBKEY -signature \
        letsencrypt-auto-source/letsencrypt-auto.sig \
        letsencrypt-auto-source/letsencrypt-auto            ; do
    echo "The signature on letsencrypt-auto is not correct."
    read -p "Would you like this script to try and sign it again [Y/n]?" response
    case $response in
      [yY][eE][sS]|[yY]|"")
        tools/offline-sigrequest.sh || true;;
      *)
        ;;
    esac
done

# This signature is not quite as strong, but easier for people to verify out of band
while ! gpg2 -u "$RELEASE_GPG_KEY" --detach-sign --armor --sign --digest-algo sha256 letsencrypt-auto-source/letsencrypt-auto; do
    echo "Unable to sign letsencrypt-auto using $RELEASE_KEY."
    echo "Make sure your OpenPGP card is in your computer if you are using one."
    echo "You may need to take the card out and put it back in again."
    read -p "Press enter to try signing again."
done
# We can't rename the openssl letsencrypt-auto.sig for compatibility reasons,
# but we can use the right name for certbot-auto.asc from day one
mv letsencrypt-auto-source/letsencrypt-auto.asc letsencrypt-auto-source/certbot-auto.asc

# copy leauto to the root, overwriting the previous release version
cp -p letsencrypt-auto-source/letsencrypt-auto certbot-auto
cp -p letsencrypt-auto-source/letsencrypt-auto letsencrypt-auto

git add certbot-auto letsencrypt-auto letsencrypt-auto-source docs/cli-help.txt
git diff --cached
while ! git commit --gpg-sign="$RELEASE_GPG_KEY" -m "Release $version"; do
    echo "Unable to sign the release commit using git."
    echo "You may have to configure git to use gpg2 by running:"
    echo 'git config --global gpg.program $(command -v gpg2)'
    read -p "Press enter to try signing again."
done
git tag --local-user "$RELEASE_GPG_KEY" --sign --message "Release $version" "$tag"

cd ..
echo Now in $PWD
name=${root_without_le%.*}
ext="${root_without_le##*.}"
rev="$(git rev-parse --short HEAD)"
echo tar cJvf $name.$rev.tar.xz $name.$rev
echo gpg2 -U $RELEASE_GPG_KEY --detach-sign --armor $name.$rev.tar.xz
cd ~-

# Add master section to CHANGELOG.md
header=$(head -n 4 CHANGELOG.md)
body=$(sed s/nextversion/$nextversion/ tools/_changelog_top.txt)
footer=$(tail -n +5 CHANGELOG.md)
echo "$header

$body

$footer" > CHANGELOG.md
git add CHANGELOG.md
git diff --cached
git commit -m "Add contents to CHANGELOG.md for next version"

echo "New root: $root"
echo "Test commands (in the letstest repo):"
echo 'python multitester.py targets.yaml $AWS_KEY $USERNAME scripts/test_leauto_upgrades.sh --alt_pip $YOUR_PIP_REPO --branch public-beta'
echo 'python multitester.py  targets.yaml $AWK_KEY $USERNAME scripts/test_letsencrypt_auto_certonly_standalone.sh --branch candidate-0.1.1'
echo 'python multitester.py --saveinstances targets.yaml $AWS_KEY $USERNAME scripts/test_apache2.sh'
echo "In order to upload packages run the following command:"
echo twine upload "$root/dist.$version/*/*"

if [ "$RELEASE_BRANCH" = candidate-"$version" ] ; then
    SetVersion "$nextversion".dev0
    letsencrypt-auto-source/build.py
    git add letsencrypt-auto-source/letsencrypt-auto
    git diff
    git commit -m "Bump version to $nextversion"
fi
