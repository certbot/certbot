"""
Helper classes for SSPI authentication via the win32security module.

SSPI authentication involves a token-exchange "dance", the exact details
of which depends on the authentication provider used.  There are also
a number of complex flags and constants that need to be used - in most
cases, there are reasonable defaults.

These classes attempt to hide these details from you until you really need
to know.  They are not designed to handle all cases, just the common ones.
If you need finer control than offered here, just use the win32security
functions directly.
"""
# Based on Roger Upole's sspi demos.
# $Id$
import win32security, sspicon

error = win32security.error

class _BaseAuth(object):
    def __init__(self):
        self.reset()

    def reset(self):
        """Reset everything to an unauthorized state"""
        self.ctxt = None
        self.authenticated = False
        # The next seq_num for an encrypt/sign operation
        self.next_seq_num = 0

    def _get_next_seq_num(self):
        """Get the next sequence number for a transmission.  Default
        implementation is to increment a counter
        """
        ret = self.next_seq_num
        self.next_seq_num = self.next_seq_num + 1
        return ret

    def encrypt(self, data):
        """Encrypt a string, returning a tuple of (encrypted_data, encryption_data).
        These can be passed to decrypt to get back the original string.
        """
        pkg_size_info=self.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        trailersize=pkg_size_info['SecurityTrailer']

        encbuf=win32security.PySecBufferDescType()
        encbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        encbuf.append(win32security.PySecBufferType(trailersize, sspicon.SECBUFFER_TOKEN))
        encbuf[0].Buffer=data
        self.ctxt.EncryptMessage(0,encbuf,self._get_next_seq_num())
        return encbuf[0].Buffer, encbuf[1].Buffer

    def decrypt(self, data, trailer):
        """Decrypt a previously encrypted string, returning the orignal data"""
        encbuf=win32security.PySecBufferDescType()
        encbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        encbuf.append(win32security.PySecBufferType(len(trailer), sspicon.SECBUFFER_TOKEN))
        encbuf[0].Buffer=data
        encbuf[1].Buffer=trailer
        self.ctxt.DecryptMessage(encbuf,self._get_next_seq_num())
        return encbuf[0].Buffer

    def sign(self, data):
        """sign a string suitable for transmission, returning the signature.
        Passing the data and signature to verify will determine if the data
        is unchanged.
        """
        pkg_size_info=self.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        sigsize=pkg_size_info['MaxSignature']
        sigbuf=win32security.PySecBufferDescType()
        sigbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        sigbuf.append(win32security.PySecBufferType(sigsize, sspicon.SECBUFFER_TOKEN))
        sigbuf[0].Buffer=data

        self.ctxt.MakeSignature(0,sigbuf,self._get_next_seq_num())
        return sigbuf[1].Buffer

    def verify(self, data, sig):
        """Verifies data and its signature.  If verification fails, an sspi.error
        will be raised.
        """
        sigbuf=win32security.PySecBufferDescType()
        sigbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        sigbuf.append(win32security.PySecBufferType(len(sig), sspicon.SECBUFFER_TOKEN))

        sigbuf[0].Buffer=data
        sigbuf[1].Buffer=sig
        self.ctxt.VerifySignature(sigbuf,self._get_next_seq_num())

class ClientAuth(_BaseAuth):
    """Manages the client side of an SSPI authentication handshake
    """
    def __init__(self,
                 pkg_name, # Name of the package to used.
                 client_name = None, # User for whom credentials are used.
                 auth_info = None, # or a tuple of (username, domain, password)
                 targetspn = None, # Target security context provider name.
                 scflags=None, # security context flags
                 datarep=sspicon.SECURITY_NETWORK_DREP):
        if scflags is None:
            scflags = sspicon.ISC_REQ_INTEGRITY|sspicon.ISC_REQ_SEQUENCE_DETECT|\
                      sspicon.ISC_REQ_REPLAY_DETECT|sspicon.ISC_REQ_CONFIDENTIALITY
        self.scflags=scflags
        self.datarep=datarep
        self.targetspn=targetspn
        self.pkg_info=win32security.QuerySecurityPackageInfo(pkg_name)
        self.credentials, \
        self.credentials_expiry=win32security.AcquireCredentialsHandle(
                client_name, self.pkg_info['Name'],
                sspicon.SECPKG_CRED_OUTBOUND,
                None, auth_info)
        _BaseAuth.__init__(self)

    # Perform *one* step of the client authentication process.
    def authorize(self, sec_buffer_in):
        if sec_buffer_in is not None and type(sec_buffer_in) != win32security.PySecBufferDescType:
            # User passed us the raw data - wrap it into a SecBufferDesc
            sec_buffer_new=win32security.PySecBufferDescType()
            tokenbuf=win32security.PySecBufferType(self.pkg_info['MaxToken'],
                                                 sspicon.SECBUFFER_TOKEN)
            tokenbuf.Buffer=sec_buffer_in
            sec_buffer_new.append(tokenbuf)
            sec_buffer_in = sec_buffer_new
        sec_buffer_out=win32security.PySecBufferDescType()
        tokenbuf=win32security.PySecBufferType(self.pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        sec_buffer_out.append(tokenbuf)
        ## input context handle should be NULL on first call
        ctxtin=self.ctxt
        if self.ctxt is None:
            self.ctxt=win32security.PyCtxtHandleType()
        err, attr, exp=win32security.InitializeSecurityContext(
            self.credentials,
            ctxtin,
            self.targetspn,
            self.scflags,
            self.datarep,
            sec_buffer_in,
            self.ctxt,
            sec_buffer_out)
        # Stash these away incase someone needs to know the state from the
        # final call.
        self.ctxt_attr = attr
        self.ctxt_expiry = exp
        
        if err in (sspicon.SEC_I_COMPLETE_NEEDED,sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            self.ctxt.CompleteAuthToken(sec_buffer_out)
        self.authenticated = err == 0
        return err, sec_buffer_out

class ServerAuth(_BaseAuth):
    """Manages the server side of an SSPI authentication handshake
    """
    def __init__(self,
                 pkg_name,
                 spn = None,
                 scflags=None,
                 datarep=sspicon.SECURITY_NETWORK_DREP):
        self.spn=spn
        self.datarep=datarep
        
        if scflags is None:
            scflags = sspicon.ASC_REQ_INTEGRITY|sspicon.ASC_REQ_SEQUENCE_DETECT|\
                      sspicon.ASC_REQ_REPLAY_DETECT|sspicon.ASC_REQ_CONFIDENTIALITY
        # Should we default to sspicon.KerbAddExtraCredentialsMessage
        # if pkg_name=='Kerberos'?
        self.scflags=scflags

        self.pkg_info=win32security.QuerySecurityPackageInfo(pkg_name)

        self.credentials, \
        self.credentials_expiry=win32security.AcquireCredentialsHandle(spn,
                self.pkg_info['Name'], sspicon.SECPKG_CRED_INBOUND, None, None)
        _BaseAuth.__init__(self)

    # Perform *one* step of the server authentication process.
    def authorize(self, sec_buffer_in):
        if sec_buffer_in is not None and type(sec_buffer_in) != win32security.PySecBufferDescType:
            # User passed us the raw data - wrap it into a SecBufferDesc
            sec_buffer_new=win32security.PySecBufferDescType()
            tokenbuf=win32security.PySecBufferType(self.pkg_info['MaxToken'],
                                                 sspicon.SECBUFFER_TOKEN)
            tokenbuf.Buffer=sec_buffer_in
            sec_buffer_new.append(tokenbuf)
            sec_buffer_in = sec_buffer_new

        sec_buffer_out=win32security.PySecBufferDescType()
        tokenbuf=win32security.PySecBufferType(self.pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        sec_buffer_out.append(tokenbuf)
        ## input context handle is None initially, then handle returned from last call thereafter
        ctxtin=self.ctxt
        if self.ctxt is None:
            self.ctxt=win32security.PyCtxtHandleType()
        err, attr, exp = win32security.AcceptSecurityContext(self.credentials, ctxtin,
            sec_buffer_in, self.scflags,
            self.datarep, self.ctxt, sec_buffer_out)

        # Stash these away incase someone needs to know the state from the
        # final call.
        self.ctxt_attr = attr
        self.ctxt_expiry = exp

        if err in (sspicon.SEC_I_COMPLETE_NEEDED,sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            self.ctxt.CompleteAuthToken(sec_buffer_out)
        self.authenticated = err == 0
        return err, sec_buffer_out

if __name__=='__main__':
   # Setup the 2 contexts.
    sspiclient=ClientAuth("NTLM")
    sspiserver=ServerAuth("NTLM")
    
    # Perform the authentication dance, each loop exchanging more information
    # on the way to completing authentication.
    sec_buffer=None
    while 1:
        err, sec_buffer = sspiclient.authorize(sec_buffer)
        err, sec_buffer = sspiserver.authorize(sec_buffer)
        if err==0:
            break
    data = "hello".encode("ascii") # py3k-friendly
    sig = sspiclient.sign(data)
    sspiserver.verify(data, sig)

    data, key = sspiclient.encrypt(data)
    assert sspiserver.decrypt(data, key) == data
    print("cool!")
