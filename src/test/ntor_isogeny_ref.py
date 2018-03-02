# Basically, a mirror to the ntor_ref.py
# We don't have a python SIDH impl; Calling it from C doesn't sound fun.

import binascii
try:
    import curve25519
    curve25519mod = curve25519.keys
except ImportError:
    curve25519 = None
    import slownacl_curve25519
    curve25519mod = slownacl_curve25519

import sys
import subprocess

class PrivateKey(curve25519mod.Private):
    """As curve25519mod.Private, but doesn't regenerate its public key
       every time you ask for it.
    """
    def __init__(self):
        curve25519mod.Private.__init__(self)
        self._memo_public = None

    def get_public(self):
        if self._memo_public is None:
            self._memo_public = curve25519mod.Private.get_public(self)

        return self._memo_public

def test_tor_sidh():
    """
       Call the test-ntor-isogeny-cl command-line program to make 
       sure we can interoperate with Tor's ntor_{sike,sidh} handshakes.
    """

    enhex=lambda s: binascii.b2a_hex(s)
    dehex=lambda s: binascii.a2b_hex(s.strip())

    PROG = b"./src/test/test-ntor-isogeny-cl"
    def tor_client1(node_id, pubkey_B):
        " returns (msg, state) "
        p = subprocess.Popen([PROG, b"client1_sidh", enhex(node_id),
                              enhex(pubkey_B.serialize())],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())
    def tor_server1(seckey_b, node_id, msg, n):
        " returns (msg, keys) "
        p = subprocess.Popen([PROG, "server1_sidh", enhex(seckey_b.serialize()),
                              enhex(node_id), enhex(msg), str(n)],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())
    def tor_client2(state, msg, n):
        " returns (keys,) "
        p = subprocess.Popen([PROG, "client2_sidh", enhex(state),
                              enhex(msg), str(n)],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())

    node_id = b"thisisatornodeid$#%^"
    seckey_b = PrivateKey()
    pubkey_B = seckey_b.get_public()

    # Do a pure-Tor handshake
    c2s_msg, c_state = tor_client1(node_id, pubkey_B)
    s2c_msg, s_keys = tor_server1(seckey_b, node_id, c2s_msg, 90)
    c_keys, = tor_client2(c_state, s2c_msg, 90)
    assert c_keys == s_keys
    assert len(c_keys) == 90

    print("SIDH OK")

def test_tor_sike():
    """
       Call the test-ntor-isogeny-cl command-line program to make 
       sure we can interoperate with Tor's ntor_{sike,sidh} handshakes.
    """

    enhex=lambda s: binascii.b2a_hex(s)
    dehex=lambda s: binascii.a2b_hex(s.strip())

    PROG = b"./src/test/test-ntor-isogeny-cl"
    def tor_client1(node_id, pubkey_B):
        " returns (msg, state) "
        p = subprocess.Popen([PROG, b"client1_sike", enhex(node_id),
                              enhex(pubkey_B.serialize())],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())
    def tor_server1(seckey_b, node_id, msg, n):
        " returns (msg, keys) "
        p = subprocess.Popen([PROG, "server1_sike", enhex(seckey_b.serialize()),
                              enhex(node_id), enhex(msg), str(n)],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())
    def tor_client2(state, msg, n):
        " returns (keys,) "
        p = subprocess.Popen([PROG, "client2_sike", enhex(state),
                              enhex(msg), str(n)],
                             stdout=subprocess.PIPE)
        return map(dehex, p.stdout.readlines())

    node_id = b"thisisatornodeid$#%^"
    seckey_b = PrivateKey()
    pubkey_B = seckey_b.get_public()

    # Do a pure-Tor handshake
    c2s_msg, c_state = tor_client1(node_id, pubkey_B)
    s2c_msg, s_keys = tor_server1(seckey_b, node_id, c2s_msg, 90)
    c_keys, = tor_client2(c_state, s2c_msg, 90)
    assert c_keys == s_keys
    assert len(c_keys) == 90

    print("SIKE OK")

def test_tor_demo():
    """
        Call the demo function of test_ntor_isogeny_cl.
    """

    PROG = b"./src/test/test-ntor-isogeny-cl"
    p = subprocess.Popen([PROG, "demo"], stdout=subprocess.PIPE)
    return 0

if __name__ == '__main__':
    if sys.argv[1] == 'test-tor-sike':
        test_tor_sike()
    elif sys.argv[1] == 'test-tor-sidh':
        test_tor_sidh()
    elif sys.argv[1] == 'test-tor-demo':
        test_tor_demo()
    else:
        print("You've screwed up, read my code. ")
