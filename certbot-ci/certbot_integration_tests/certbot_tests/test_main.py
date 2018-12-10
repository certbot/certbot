import requests
import urllib3


def test_hello_1(request, worker_id):
    assert request.config.acme_xdist[worker_id]
    try:
        response = requests.get(request.config.acme_xdist[worker_id]['directory_url'], verify=False)
        response.raise_for_status()
        assert response.json()
        response.close()
    except urllib3.exceptions.InsecureRequestWarning:
        pass


def test_hello_2(request, worker_id):
    assert request.config.acme_xdist[worker_id]
    try:
        response = requests.get(request.config.acme_xdist[worker_id]['directory_url'], verify=False)
        response.raise_for_status()
        assert response.json()
        response.close()
    except urllib3.exceptions.InsecureRequestWarning:
        pass

