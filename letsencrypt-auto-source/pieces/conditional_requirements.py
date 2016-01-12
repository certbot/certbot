"""Spit out additional pinned requirements depending on the Python version."""
from sys import version_info


if __name__ == '__main__':
    if version_info < (2, 7, 9):
        print """
# sha256: 6MFV_evZxLywgQtO0BrhmHVUse4DTddTLXuP2uOKYnQ
ndg-httpsclient==0.4.0

# sha256: YfnZnjzvZf6xv-Oi7vepPrk4GdNFv1S81C9OY9UgTa4
# sha256: GAKm3TIEXkcqQZ2xRBrsq0adM-DSdJ4ZKr3sUhAXJK8
# sha256: NQJc2UIsllBJEvBOLxX-eTkKhZe0MMLKXQU0z5MJ_6A
# sha256: L5btWgwynKFiMLMmyhK3Rh7I9l4L4-T5l1FvNr-Co0U
# sha256: KP7kQheZHPrZ5qC59-PyYEHiHryWYp6U5YXM0F1J-mU
# sha256: Mm56hUoX-rB2kSBHR2lfj2ktZ0WIo1XEQfsU9mC_Tmg
# sha256: zaWpBIVwnKZ5XIYFbD5f5yZgKLBeU_HVJ_35OmNlprg
# sha256: DLKhR0K1Q_3Wj5MaFM44KRhu0rGyJnoGeHOIyWst2b4
# sha256: UZH_a5Em0sA53Yf4_wJb7SdLrwf6eK-kb1VrGtcmXW4
# sha256: gyPgNjey0HLMcEEwC6xuxEjDwolQq0A3YDZ4jpoa9ik
# sha256: hTys2W0fcB3dZ6oD7MBfUYkBNbcmLpInEBEvEqLtKn8
pyasn1==0.1.9
"""
    if version_info < (2, 7):
        print """
# sha256: wxZH7baf09RlqEfqMVfTe-0flfGXYLEaR6qRwEtmYxQ
# sha256: YrCJpVvh2JSc0rx-DfC9254Cj678jDIDjMhIYq791uQ
argparse==1.4.0
"""
