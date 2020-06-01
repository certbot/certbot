import unittest
import struct
import sys
import os
import pywintypes
import win32event, win32api
import os
from pywin32_testutil import str2bytes, TestSkipped
import win32com.directsound.directsound as ds
# next two lines are for for debugging:
# import win32com
# import directsound as ds

WAV_FORMAT_PCM = 1
WAV_HEADER_SIZE = struct.calcsize('<4sl4s4slhhllhh4sl')

def wav_header_unpack(data):
    (riff, riffsize, wave, fmt, fmtsize, format, nchannels, samplespersecond, 
     datarate, blockalign, bitspersample, data, datalength) \
     = struct.unpack('<4sl4s4slhhllhh4sl', data)

    if riff != str2bytes('RIFF'):
        raise ValueError('invalid wav header')
    
    if fmtsize != 16 or fmt != str2bytes('fmt ') or str2bytes(data) != 'data':
        # fmt chuck is not first chunk, directly followed by data chuck
        # It is nowhere required that they are, it is just very common
        raise ValueError('cannot understand wav header')

    wfx = pywintypes.WAVEFORMATEX()
    wfx.wFormatTag = format
    wfx.nChannels = nchannels
    wfx.nSamplesPerSec = samplespersecond
    wfx.nAvgBytesPerSec = datarate
    wfx.nBlockAlign = blockalign
    wfx.wBitsPerSample = bitspersample

    return wfx, datalength

def wav_header_pack(wfx, datasize):
    return struct.pack('<4sl4s4slhhllhh4sl', 'RIFF', 36 + datasize,
                       'WAVE', 'fmt ', 16,
                       wfx.wFormatTag, wfx.nChannels, wfx.nSamplesPerSec,
                       wfx.nAvgBytesPerSec, wfx.nBlockAlign,
                       wfx.wBitsPerSample, 'data', datasize);

class WAVEFORMATTest(unittest.TestCase):
    def test_1_Type(self):
        'WAVEFORMATEX type'
        w = pywintypes.WAVEFORMATEX()
        self.failUnless(type(w) == pywintypes.WAVEFORMATEXType)

    def test_2_Attr(self):
        'WAVEFORMATEX attribute access'
        # A wav header for a soundfile from a CD should look like this...
        w = pywintypes.WAVEFORMATEX()
        w.wFormatTag = pywintypes.WAVE_FORMAT_PCM
        w.nChannels = 2
        w.nSamplesPerSec = 44100
        w.nAvgBytesPerSec = 176400
        w.nBlockAlign = 4
        w.wBitsPerSample = 16

        self.failUnless(w.wFormatTag == 1)
        self.failUnless(w.nChannels == 2)
        self.failUnless(w.nSamplesPerSec == 44100)
        self.failUnless(w.nAvgBytesPerSec == 176400)
        self.failUnless(w.nBlockAlign == 4)
        self.failUnless(w.wBitsPerSample == 16)

class DSCAPSTest(unittest.TestCase):
    def test_1_Type(self):
        'DSCAPS type'
        c = ds.DSCAPS()
        self.failUnless(type(c) == ds.DSCAPSType)

    def test_2_Attr(self):
        'DSCAPS attribute access'
        c = ds.DSCAPS()
        c.dwFlags = 1
        c.dwMinSecondarySampleRate = 2
        c.dwMaxSecondarySampleRate = 3
        c.dwPrimaryBuffers = 4
        c.dwMaxHwMixingAllBuffers = 5
        c.dwMaxHwMixingStaticBuffers = 6
        c.dwMaxHwMixingStreamingBuffers = 7
        c.dwFreeHwMixingAllBuffers = 8
        c.dwFreeHwMixingStaticBuffers = 9
        c.dwFreeHwMixingStreamingBuffers = 10
        c.dwMaxHw3DAllBuffers = 11
        c.dwMaxHw3DStaticBuffers = 12
        c.dwMaxHw3DStreamingBuffers = 13
        c.dwFreeHw3DAllBuffers = 14
        c.dwFreeHw3DStaticBuffers = 15
        c.dwFreeHw3DStreamingBuffers = 16
        c.dwTotalHwMemBytes = 17
        c.dwFreeHwMemBytes = 18
        c.dwMaxContigFreeHwMemBytes = 19
        c.dwUnlockTransferRateHwBuffers = 20
        c.dwPlayCpuOverheadSwBuffers = 21

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwMinSecondarySampleRate == 2)
        self.failUnless(c.dwMaxSecondarySampleRate == 3)
        self.failUnless(c.dwPrimaryBuffers == 4)
        self.failUnless(c.dwMaxHwMixingAllBuffers == 5)
        self.failUnless(c.dwMaxHwMixingStaticBuffers == 6)
        self.failUnless(c.dwMaxHwMixingStreamingBuffers == 7)
        self.failUnless(c.dwFreeHwMixingAllBuffers == 8)
        self.failUnless(c.dwFreeHwMixingStaticBuffers == 9)
        self.failUnless(c.dwFreeHwMixingStreamingBuffers == 10)
        self.failUnless(c.dwMaxHw3DAllBuffers == 11)
        self.failUnless(c.dwMaxHw3DStaticBuffers == 12)
        self.failUnless(c.dwMaxHw3DStreamingBuffers == 13)
        self.failUnless(c.dwFreeHw3DAllBuffers == 14)
        self.failUnless(c.dwFreeHw3DStaticBuffers == 15)
        self.failUnless(c.dwFreeHw3DStreamingBuffers == 16)
        self.failUnless(c.dwTotalHwMemBytes == 17)
        self.failUnless(c.dwFreeHwMemBytes == 18)
        self.failUnless(c.dwMaxContigFreeHwMemBytes == 19)
        self.failUnless(c.dwUnlockTransferRateHwBuffers == 20)
        self.failUnless(c.dwPlayCpuOverheadSwBuffers == 21)

class DSBCAPSTest(unittest.TestCase):
    def test_1_Type(self):
        'DSBCAPS type'
        c = ds.DSBCAPS()
        self.failUnless(type(c) == ds.DSBCAPSType)

    def test_2_Attr(self):
        'DSBCAPS attribute access'
        c = ds.DSBCAPS()
        c.dwFlags = 1
        c.dwBufferBytes = 2
        c.dwUnlockTransferRate = 3
        c.dwPlayCpuOverhead = 4

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwBufferBytes == 2)
        self.failUnless(c.dwUnlockTransferRate == 3)
        self.failUnless(c.dwPlayCpuOverhead == 4)

class DSCCAPSTest(unittest.TestCase):
    def test_1_Type(self):
        'DSCCAPS type'
        c = ds.DSCCAPS()
        self.failUnless(type(c) == ds.DSCCAPSType)

    def test_2_Attr(self):
        'DSCCAPS attribute access'
        c = ds.DSCCAPS()
        c.dwFlags = 1
        c.dwFormats = 2
        c.dwChannels = 4

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwFormats == 2)
        self.failUnless(c.dwChannels == 4)

class DSCBCAPSTest(unittest.TestCase):
    def test_1_Type(self):
        'DSCBCAPS type'
        c = ds.DSCBCAPS()
        self.failUnless(type(c) == ds.DSCBCAPSType)

    def test_2_Attr(self):
        'DSCBCAPS attribute access'
        c = ds.DSCBCAPS()
        c.dwFlags = 1
        c.dwBufferBytes = 2

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwBufferBytes == 2)

class DSBUFFERDESCTest(unittest.TestCase):
    def test_1_Type(self):
        'DSBUFFERDESC type'
        c = ds.DSBUFFERDESC()
        self.failUnless(type(c) == ds.DSBUFFERDESCType)

    def test_2_Attr(self):
        'DSBUFFERDESC attribute access'
        c = ds.DSBUFFERDESC()
        c.dwFlags = 1
        c.dwBufferBytes = 2
        c.lpwfxFormat = pywintypes.WAVEFORMATEX()
        c.lpwfxFormat.wFormatTag = pywintypes.WAVE_FORMAT_PCM
        c.lpwfxFormat.nChannels = 2
        c.lpwfxFormat.nSamplesPerSec = 44100
        c.lpwfxFormat.nAvgBytesPerSec = 176400
        c.lpwfxFormat.nBlockAlign = 4
        c.lpwfxFormat.wBitsPerSample = 16

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwBufferBytes == 2)
        self.failUnless(c.lpwfxFormat.wFormatTag == 1)
        self.failUnless(c.lpwfxFormat.nChannels == 2)
        self.failUnless(c.lpwfxFormat.nSamplesPerSec == 44100)
        self.failUnless(c.lpwfxFormat.nAvgBytesPerSec == 176400)
        self.failUnless(c.lpwfxFormat.nBlockAlign == 4)
        self.failUnless(c.lpwfxFormat.wBitsPerSample == 16)

    def invalid_format(self, c):
        c.lpwfxFormat = 17

    def test_3_invalid_format(self):
        'DSBUFFERDESC invalid lpwfxFormat assignment'
        c = ds.DSBUFFERDESC()
        self.failUnlessRaises(ValueError, self.invalid_format, c)

class DSCBUFFERDESCTest(unittest.TestCase):
    def test_1_Type(self):
        'DSCBUFFERDESC type'
        c = ds.DSCBUFFERDESC()
        self.failUnless(type(c) == ds.DSCBUFFERDESCType)

    def test_2_Attr(self):
        'DSCBUFFERDESC attribute access'
        c = ds.DSCBUFFERDESC()
        c.dwFlags = 1
        c.dwBufferBytes = 2
        c.lpwfxFormat = pywintypes.WAVEFORMATEX()
        c.lpwfxFormat.wFormatTag = pywintypes.WAVE_FORMAT_PCM
        c.lpwfxFormat.nChannels = 2
        c.lpwfxFormat.nSamplesPerSec = 44100
        c.lpwfxFormat.nAvgBytesPerSec = 176400
        c.lpwfxFormat.nBlockAlign = 4
        c.lpwfxFormat.wBitsPerSample = 16

        self.failUnless(c.dwFlags == 1)
        self.failUnless(c.dwBufferBytes == 2)
        self.failUnless(c.lpwfxFormat.wFormatTag == 1)
        self.failUnless(c.lpwfxFormat.nChannels == 2)
        self.failUnless(c.lpwfxFormat.nSamplesPerSec == 44100)
        self.failUnless(c.lpwfxFormat.nAvgBytesPerSec == 176400)
        self.failUnless(c.lpwfxFormat.nBlockAlign == 4)
        self.failUnless(c.lpwfxFormat.wBitsPerSample == 16)

    def invalid_format(self, c):
        c.lpwfxFormat = 17

    def test_3_invalid_format(self):
        'DSCBUFFERDESC invalid lpwfxFormat assignment'
        c = ds.DSCBUFFERDESC()
        self.failUnlessRaises(ValueError, self.invalid_format, c)

class DirectSoundTest(unittest.TestCase):
    # basic tests - mostly just exercise the functions
    
    def testEnumerate(self):
        '''DirectSoundEnumerate() sanity tests'''

        devices = ds.DirectSoundEnumerate()
        # this might fail on machines without a sound card
        self.failUnless(len(devices))
        # if we have an entry, it must be a tuple of size 3
        self.failUnless(len(devices[0]) == 3)
        
    def testCreate(self):
        '''DirectSoundCreate()'''
        d = ds.DirectSoundCreate(None, None)

    def testPlay(self):
        '''Mesdames et Messieurs, la cour de Devin Dazzle'''
        # look for the test file in various places
        candidates = [
            os.path.dirname(__file__),
            os.path.dirname(sys.argv[0]),
            # relative to 'testall.py' in the win32com test suite.
            os.path.join(os.path.dirname(sys.argv[0]),
                         '../../win32comext/directsound/test'),
            '.',
        ]
        for candidate in candidates:
            fname=os.path.join(candidate, "01-Intro.wav")
            if os.path.isfile(fname):
                break
        else:
            raise TestSkipped("Can't find test .wav file to play")

        f = open(fname, 'rb')
        hdr = f.read(WAV_HEADER_SIZE)
        wfx, size = wav_header_unpack(hdr)

        d = ds.DirectSoundCreate(None, None)
        d.SetCooperativeLevel(None, ds.DSSCL_PRIORITY)

        sdesc = ds.DSBUFFERDESC()
        sdesc.dwFlags = ds.DSBCAPS_STICKYFOCUS | ds.DSBCAPS_CTRLPOSITIONNOTIFY
        sdesc.dwBufferBytes = size
        sdesc.lpwfxFormat = wfx

        buffer = d.CreateSoundBuffer(sdesc, None)

        event = win32event.CreateEvent(None, 0, 0, None)
        notify = buffer.QueryInterface(ds.IID_IDirectSoundNotify)

        notify.SetNotificationPositions((ds.DSBPN_OFFSETSTOP, event))

        buffer.Update(0, f.read(size))

        buffer.Play(0)

        win32event.WaitForSingleObject(event, -1)

class DirectSoundCaptureTest(unittest.TestCase):
    # basic tests - mostly just exercise the functions
    
    def testEnumerate(self):
        '''DirectSoundCaptureEnumerate() sanity tests'''

        devices = ds.DirectSoundCaptureEnumerate()
        # this might fail on machines without a sound card
        self.failUnless(len(devices))
        # if we have an entry, it must be a tuple of size 3
        self.failUnless(len(devices[0]) == 3)
        
    def testCreate(self):
        '''DirectSoundCreate()'''
        d = ds.DirectSoundCaptureCreate(None, None)

    def testRecord(self):
        d = ds.DirectSoundCaptureCreate(None, None)

        sdesc = ds.DSCBUFFERDESC()
        sdesc.dwBufferBytes = 352800 # 2 seconds
        sdesc.lpwfxFormat = pywintypes.WAVEFORMATEX()
        sdesc.lpwfxFormat.wFormatTag = pywintypes.WAVE_FORMAT_PCM
        sdesc.lpwfxFormat.nChannels = 2
        sdesc.lpwfxFormat.nSamplesPerSec = 44100
        sdesc.lpwfxFormat.nAvgBytesPerSec = 176400
        sdesc.lpwfxFormat.nBlockAlign = 4
        sdesc.lpwfxFormat.wBitsPerSample = 16

        buffer = d.CreateCaptureBuffer(sdesc)

        event = win32event.CreateEvent(None, 0, 0, None)
        notify = buffer.QueryInterface(ds.IID_IDirectSoundNotify)

        notify.SetNotificationPositions((ds.DSBPN_OFFSETSTOP, event))

        buffer.Start(0)

        win32event.WaitForSingleObject(event, -1)
        event.Close()

        data = buffer.Update(0, 352800)
        fname=os.path.join(win32api.GetTempPath(), 'test_directsound_record.wav')
        f = open(fname, 'wb')
        f.write(wav_header_pack(sdesc.lpwfxFormat, 352800))
        f.write(data)
        f.close()

if __name__ == '__main__':
    unittest.main()
