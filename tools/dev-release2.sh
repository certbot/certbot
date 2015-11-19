#!/bin/sh -xe

# This script should be put into `./tools/dev-release2.sh`, in the repo.
#
# 1. Create packages.
#
#   script -c ./tools/dev-release2.sh log2
#   mv *.tar.xz* dev-releases/
#   mv log2 dev-releases/${version?}.log
#
# 2. Test them.
#
# Copy stuff to VPS and EFF server:
#
#   rsync -avzP dev-releases/ le:~/le-dev-releases
#   rsync -avzP dev-releases/ ubuntu@letsencrypt-demo.org:~/le-dev-releases
#
# Now test using similar method as in `dev-release.sh` script. On
# remote server `cd ~/le-dev-releases`, extract tarballs, `cd
# $dir/dist.$version; python -m SimpleHTTPServer 1234`. In another
# terminal, outside `le-dev-releases` directory, create new
# virtualenv, `for pkg in setuptools pip wheel; do pip install -U $pkg; done`, 
# confirm new installed versions by `pip list`, and try
# to install stuff with `pip install --extra-index-url  http://localhost:$PORT
#`. Then play with the client until you're sure
# everything works :)
#
# 3. Upload.
#
# Upload to PyPI using the twine command that was printed earlier.
#
# Now, update tags in git:
#
#   git remote remove tmp || true
#   git remote add tmp /tmp/le.XXX
#   git fetch tmp
#   git push github/letsencrypt v0.0.0.dev$date
#
# Create a GitHub issue with the release information, ask someone to
# pull in the tag.

script --return --command ./tools/dev-release.sh log

root="$(basename `grep -E '^/tmp/le' log | head -n1 | tr -d "\r"`)"
root_without_le="${root##le.}"
name=${root_without_le%.*}
ext="${root_without_le##*.}"
rev="$(git rev-parse --short HEAD)"
cp -r /tmp/le.$name.$ext/ $name.$rev
tar cJvf $name.$rev.tar.xz log $name.$rev
gpg --detach-sign --armor $name.$rev.tar.xz
