"""Find URLs in files and try fetching them."""
import re
import sys
import time
import threading
import requests

def check_url(filename, url, errors):
    err = load_url(filename, url)
    if err is not None:
        errors.append(err)

def load_url(filename, url):
    """
    Load a URL, returning an error string if there was a problem, otherwise None
    """
    try:
        r = requests.get(url)
        if r.status_code > 500: # Do one retry.
            time.sleep(1)
            r = requests.get(url)
        if r.status_code != 200:
            return ("Status code %d fetching %s (mentioned in %s)" %
                (r.status_code, url, filename))
    except Exception, e:
        return "Problem fetching %s (mentioned in %s): %s" % (url, filename, e.__str__())
    return None

errors = []
threads = []
urls = {}
for filename in sys.argv[1:]:
    contents = open(filename).read()
    for url in re.findall("https?://[^\s>,)`'\"\]]+", contents):
        url = url.rstrip("_.>,)`'\"\]")
        url = re.sub("#.*", "", url)
        if url not in urls:
            t = threading.Thread(target=check_url, args=(filename, url, errors))
            threads.append(t)
            t.start()
            urls[url] = 1

for t in threads:
    t.join()

result = 0
for e in errors:
    if e is not None:
        sys.stderr.write(e + "\n")
    result = 1
sys.exit(result)
