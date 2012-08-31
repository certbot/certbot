"""
Pure Python GeoIP API. The API is based off of U{MaxMind's C-based Python API<http://www.maxmind.com/app/python>},
but the code itself is based on the U{pure PHP5 API<http://pear.php.net/package/Net_GeoIP/>}
by Jim Winstead and Hans Lellelid.

It is mostly a drop-in replacement, except the
C{new} and C{open} methods are gone. You should instantiate the L{GeoIP} class yourself:

C{gi = GeoIP('/path/to/GeoIP.dat', pygeoip.MEMORY_CACHE)}

@author: Jennifer Ennis <zaylea at gmail dot com>

@license:
Copyright(C) 2004 MaxMind LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/lgpl.txt>.
"""

from __future__ import with_statement
import os
import math
import socket
import mmap

from const import *
from util import ip2long

class GeoIPError(Exception):
    pass

class GeoIPMetaclass(type):
    
    def __new__(cls, *args, **kwargs):
        """
        Singleton method to gets an instance without reparsing the db. Unique
        instances are instantiated based on the filename of the db. Flags are
        ignored for this, i.e. if you initialize one with STANDARD flag (default)
        and then try later to initialize with MEMORY_CACHE, it will still
        return the STANDARD one.
        """
        
        if not hasattr(cls, '_instances'):
            cls._instances = {}
        
        if len(args) > 0:
            filename = args[0]
        elif 'filename' in kwargs:
            filename = kwargs['filename']
            
        if not filename in cls._instances:
            cls._instances[filename] = type.__new__(cls, *args, **kwargs)
        
        return cls._instances[filename]
        
GeoIPBase = GeoIPMetaclass('GeoIPBase', (object,), {})

class GeoIP(GeoIPBase):
    
    def __init__(self, filename, flags=0):
        """
        Initialize the class.
        
        @param filename: path to a geoip database
        @type filename: str
        @param flags: flags that affect how the database is processed.
            Currently the only supported flags are STANDARD, MEMORY_CACHE, and
            MMAP_CACHE.
        @type flags: int
        """
        self._filename = filename
        self._flags = flags
        
        if self._flags & MMAP_CACHE:
            with open(filename, 'rb') as f:
                self._filehandle = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        
        else:
            self._filehandle = open(filename, 'rb')
            
            if self._flags & MEMORY_CACHE:
                self._memoryBuffer = self._filehandle.read()
            
        self._setup_segments()
    
    def _setup_segments(self):
        """
        Parses the database file to determine what kind of database is being used and setup
        segment sizes and start points that will be used by the seek*() methods later.
        """
        self._databaseType = COUNTRY_EDITION
        self._recordLength = STANDARD_RECORD_LENGTH
        
        filepos = self._filehandle.tell()
        self._filehandle.seek(-3, os.SEEK_END)
        
        for i in range(STRUCTURE_INFO_MAX_SIZE):
            delim = self._filehandle.read(3)

            if delim == (chr(255) * 3):
                self._databaseType = ord(self._filehandle.read(1))
                
                if (self._databaseType >= 106):
                    # backwards compatibility with databases from April 2003 and earlier
                    self._databaseType -= 105
                
                if self._databaseType == REGION_EDITION_REV0:
                    self._databaseSegments = STATE_BEGIN_REV0
                    
                elif self._databaseType == REGION_EDITION_REV1:
                    self._databaseSegments = STATE_BEGIN_REV1
                    
                elif self._databaseType in (CITY_EDITION_REV0,
                                            CITY_EDITION_REV1,
                                            ORG_EDITION,
                                            ISP_EDITION,
                                            ASNUM_EDITION):
                    self._databaseSegments = 0
                    buf = self._filehandle.read(SEGMENT_RECORD_LENGTH)
                    
                    for j in range(SEGMENT_RECORD_LENGTH):
                        self._databaseSegments += (ord(buf[j]) << (j * 8))
                        
                    if self._databaseType in (ORG_EDITION, ISP_EDITION):
                        self._recordLength = ORG_RECORD_LENGTH
                        
                break
            else:
                self._filehandle.seek(-4, os.SEEK_CUR)
                
        if self._databaseType == COUNTRY_EDITION:
            self._databaseSegments = COUNTRY_BEGIN
            
        self._filehandle.seek(filepos, os.SEEK_SET)
    
    def _lookup_country_id(self, addr):
        """
        Get the country index.
        
        This method is called by the _lookupCountryCode and _lookupCountryName
        methods. It looks up the index ('id') for the country which is the key
        for the code and name.
        
        @param addr: The IP address
        @type addr: str
        @return: network byte order 32-bit integer
        @rtype: int
        """
        
        ipnum = ip2long(addr)
        
        if not ipnum:
            raise ValueError("Invalid IP address: %s" % addr)
        
        if self._databaseType != COUNTRY_EDITION:
            raise GeoIPError('Invalid database type; country_* methods expect '\
                             'Country database')
        
        return self._seek_country(ipnum) - COUNTRY_BEGIN
    
    def _seek_country(self, ipnum):
        """
        Using the record length and appropriate start points, seek to the
        country that corresponds to the converted IP address integer.
        
        @param ipnum: result of ip2long conversion
        @type ipnum: int
        @return: offset of start of record
        @rtype: int
        """
        offset = 0
        
        for depth in range(31, -1, -1):
            
            if self._flags & MEMORY_CACHE:
                startIndex = 2 * self._recordLength * offset
                length = 2 * self._recordLength
                endIndex = startIndex + length
                buf = self._memoryBuffer[startIndex:endIndex]
            else:
                self._filehandle.seek(2 * self._recordLength * offset, os.SEEK_SET)
                buf = self._filehandle.read(2 * self._recordLength)
            
            x = [0,0]
            
            for i in range(2):        
                for j in range(self._recordLength):
                    x[i] += ord(buf[self._recordLength * i + j]) << (j * 8)    
            
            if ipnum & (1 << depth):
    
                if x[1] >= self._databaseSegments:
                    return x[1]
                    
                offset = x[1]
            
            else:
                
                if x[0] >= self._databaseSegments:
                    return x[0]
                    
                offset = x[0]
                
            
        raise Exception('Error traversing database - perhaps it is corrupt?')
    
    def _get_org(self, ipnum):
        """
        Seek and return organization (or ISP) name for converted IP addr.
        @param ipnum: Converted IP address
        @type ipnum: int
        @return: org/isp name
        @rtype: str
        """
        
        seek_org = self._seek_country(ipnum)
        if seek_org == self._databaseSegments:
            return None
        
        record_pointer = seek_org + (2 * self._recordLength - 1) * self._databaseSegments
        
        self._filehandle.seek(record_pointer, os.SEEK_SET)
        
        org_buf = self._filehandle.read(MAX_ORG_RECORD_LENGTH)
        
        return org_buf[:org_buf.index(chr(0))]
    
    def _get_region(self, ipnum):
        """
        Seek and return the region info (dict containing country_code and region_name).
        
        @param ipnum: converted IP address
        @type ipnum: int
        @return: dict containing country_code and region_name
        @rtype: dict
        """
        country_code = ''
        region = ''
        
        if self._databaseType == REGION_EDITION_REV0:
            seek_country = self._seek_country(ipnum)
            seek_region = seek_country - STATE_BEGIN_REV0
            if seek_region >= 1000:
                country_code = 'US'
                region = ''.join([chr((seek_region / 1000) / 26 + 65), chr((seek_region / 1000) % 26 + 65)])
            else:
                country_code = COUNTRY_CODES[seek_region]
                region = ''
        elif self._databaseType == REGION_EDITION_REV1:
            seek_country = self._seek_country(ipnum)
            seek_region = seek_country - STATE_BEGIN_REV1
            if seek_region < US_OFFSET:
                country_code = '';
                region = ''
            elif seek_region < CANADA_OFFSET:
                country_code = 'US'
                region = ''.join([chr((seek_region - US_OFFSET) / 26 + 65), chr((seek_region - US_OFFSET) % 26 + 65)])
            elif seek_region  < WORLD_OFFSET:
                country_code = 'CA'
                region = ''.join([chr((seek_region - CANADA_OFFSET) / 26 + 65), chr((seek_region - CANADA_OFFSET) % 26 + 65)])
            else:
                i = (seek_region - WORLD_OFFSET) / FIPS_RANGE
                if i in COUNTRY_CODES:
                    country_code = COUNTRY_CODES[(seek_region - WORLD_OFFSET) / FIPS_RANGE]
                else:
                    country_code = ''
                region = ''
                
        elif self._databaseType in (CITY_EDITION_REV0, CITY_EDITION_REV1):
            rec = self._get_record(ipnum)
            country_code = rec['country_code'] 
            region = rec['region_name']
            
        return {'country_code' : country_code, 'region_name' : region }  
    
    def _get_record(self, ipnum):
        """
        Populate location dict for converted IP.
        
        @param ipnum: converted IP address
        @type ipnum: int
        @return: dict with country_code, country_code3, country_name,
            region, city, postal_code, latitude, longitude,
            dma_code, metro_code, area_code, region_name, time_zone
        @rtype: dict
        """
        seek_country = self._seek_country(ipnum)
        if seek_country == self._databaseSegments:
            return None
        
        record_pointer = seek_country + (2 * self._recordLength - 1) * self._databaseSegments
        
        self._filehandle.seek(record_pointer, os.SEEK_SET)
        record_buf = self._filehandle.read(FULL_RECORD_LENGTH)
        
        record = {}
        
        record_buf_pos = 0
        char = ord(record_buf[record_buf_pos])
        record['country_code'] = COUNTRY_CODES[char]
        record['country_code3'] = COUNTRY_CODES3[char]
        record['country_name'] = COUNTRY_NAMES[char]
        record_buf_pos += 1
        str_length = 0
        
        # get region
        char = ord(record_buf[record_buf_pos+str_length])
        while (char != 0):
            str_length += 1
            char = ord(record_buf[record_buf_pos+str_length])
            
        if str_length > 0:
            record['region_name'] = record_buf[record_buf_pos:record_buf_pos+str_length]
            
        record_buf_pos += str_length + 1
        str_length = 0
        
        # get city
        char = ord(record_buf[record_buf_pos+str_length])
        while (char != 0):
            str_length += 1
            char = ord(record_buf[record_buf_pos+str_length])
        
        if str_length > 0:
            record['city'] = record_buf[record_buf_pos:record_buf_pos+str_length]
        
        record_buf_pos += str_length + 1
        str_length = 0
        
        # get the postal code
        char = ord(record_buf[record_buf_pos+str_length])
        while (char != 0):
            str_length += 1
            char = ord(record_buf[record_buf_pos+str_length])
        
        if str_length > 0:
            record['postal_code'] = record_buf[record_buf_pos:record_buf_pos+str_length]
        else:
            record['postal_code'] = None
            
        record_buf_pos += str_length + 1
        str_length = 0
        
        latitude = 0
        longitude = 0
        for j in range(3):
            char = ord(record_buf[record_buf_pos])
            record_buf_pos += 1
            latitude += (char << (j * 8))
            
        record['latitude'] = (latitude/10000.0) - 180.0
        
        for j in range(3):
            char = ord(record_buf[record_buf_pos])
            record_buf_pos += 1
            longitude += (char << (j * 8))
            
        record['longitude'] = (longitude/10000.0) - 180.0
        
        if self._databaseType == CITY_EDITION_REV1:
            dmaarea_combo = 0
            if record['country_code'] == 'US':
                for j in range(3):
                    char = ord(record_buf[record_buf_pos])
                    record_buf_pos += 1
                    dmaarea_combo += (char << (j*8))
                
                record['dma_code'] = int(math.floor(dmaarea_combo/1000))
                record['area_code'] = dmaarea_combo%1000
        else:
            record['dma_code'] = 0
            record['area_code'] = 0
                
        return record
    
    def country_code_by_addr(self, addr):
        """
        Returns 2-letter country code (e.g. 'US') for specified IP address.
        Use this method if you have a Country, Region, or City database.
        
        @param addr: IP address
        @type addr: str
        @return: 2-letter country code
        @rtype: str
        """
        try:
            if self._databaseType == COUNTRY_EDITION:
                country_id = self._lookup_country_id(addr)   
                return COUNTRY_CODES[country_id]
            elif self._databaseType in (REGION_EDITION_REV0, REGION_EDITION_REV1,
                                          CITY_EDITION_REV0, CITY_EDITION_REV1):
                return self.region_by_addr(addr)['country_code']
            else:
                raise GeoIPError('Invalid database type; country_* methods expect '\
                                 'Country, City, or Region database')
            
        except ValueError:
            raise GeoIPError('*_by_addr methods only accept IP addresses. Use *_by_name for hostnames. (Address: %s)' % addr)
            
    def country_code_by_name(self, hostname):
        """
        Returns 2-letter country code (e.g. 'US') for specified hostname.
        Use this method if you have a Country, Region, or City database.
        
        @param hostname: host name
        @type hostname: str
        @return: 2-letter country code
        @rtype: str
        """
        addr = socket.gethostbyname(hostname)
        
        return self.country_code_by_addr(addr)
    
    def country_name_by_addr(self, addr):
        """
        Returns full country name for specified IP address.
        Use this method if you have a Country or City database.
        
        @param addr: IP address
        @type addr: str
        @return: country name
        @rtype: str
        """
        try:
            if self._databaseType == COUNTRY_EDITION:
                country_id = self._lookup_country_id(addr)
                return COUNTRY_NAMES[country_id]
            elif self._databaseType in (CITY_EDITION_REV0, CITY_EDITION_REV1):
                return self.record_by_addr(addr)['country_name']
            else:
                raise GeoIPError('Invalid database type; country_* methods expect '\
                                 'Country or City database')
        except ValueError:
            raise GeoIPError('*_by_addr methods only accept IP addresses. Use *_by_name for hostnames. (Address: %s)' % addr)
    
    def country_name_by_name(self, hostname):
        """
        Returns full country name for specified hostname.
        Use this method if you have a Country database.
        
        @param hostname: host name
        @type hostname: str
        @return: country name
        @rtype: str
        """
        addr = socket.gethostbyname(hostname)
        return self.country_name_by_addr(addr)
    
    def org_by_addr(self, addr):
        """
        Lookup the organization (or ISP) for given IP address.
        Use this method if you have an Organization/ISP database.
        
        @param addr: IP address
        @type addr: str
        @return: organization or ISP name
        @rtype: str
        """
        try:
            ipnum = ip2long(addr)
            
            if not ipnum:
                raise ValueError("Invalid IP address: %s" % addr)
            
            if self._databaseType not in (ORG_EDITION, ISP_EDITION):
                raise GeoIPError('Invalid database type; org_* methods expect '\
                                 'Org/ISP database')
                
            return self._get_org(ipnum)
        except ValueError:
            raise GeoIPError('*_by_addr methods only accept IP addresses. Use *_by_name for hostnames. (Address: %s)' % addr)
    
    def org_by_name(self, hostname):
        """
        Lookup the organization (or ISP) for hostname.
        Use this method if you have an Organization/ISP database.
        
        @param hostname: host name
        @type hostname: str
        @return: organization or ISP name
        @rtype: str
        """
        addr = socket.gethostbyname(hostname)
        
        return self.org_by_addr(addr)
    
    def record_by_addr(self, addr):
        """
        Look up the record for a given IP address.
        Use this method if you have a City database.
        
        @param addr: IP address
        @type addr: str
        @return: dict with country_code, country_code3, country_name,
            region, city, postal_code, latitude, longitude,
            dma_code, metro_code, area_code, region_name, time_zone
        @rtype: dict
        """
        try:
            ipnum = ip2long(addr)
            
            if not ipnum:
                raise ValueError("Invalid IP address: %s" % addr)
                
            if not self._databaseType in (CITY_EDITION_REV0, CITY_EDITION_REV1):
                raise GeoIPError('Invalid database type; record_* methods expect City database')
            
            return self._get_record(ipnum)
        except ValueError:
            raise GeoIPError('*_by_addr methods only accept IP addresses. Use *_by_name for hostnames. (Address: %s)' % addr)
            
    def record_by_name(self, hostname):
        """
        Look up the record for a given hostname.
        Use this method if you have a City database.
        
        @param hostname: host name
        @type hostname: str
        @return: dict with country_code, country_code3, country_name,
            region, city, postal_code, latitude, longitude,
            dma_code, metro_code, area_code, region_name, time_zone
        @rtype: dict
        """
        addr = socket.gethostbyname(hostname)
        
        return self.record_by_addr(addr)
    
    def region_by_addr(self, addr):
        """
        Lookup the region for given IP address.
        Use this method if you have a Region database.
        
        @param addr: IP address
        @type addr: str
        @return: dict containing country_code, region,
            and region_name
        @rtype: dict
        """
        try:
            ipnum = ip2long(addr)
            
            if not ipnum:
                raise ValueError("Invalid IP address: %s" % addr)
                
            if not self._databaseType in (REGION_EDITION_REV0, REGION_EDITION_REV1,
                                          CITY_EDITION_REV0, CITY_EDITION_REV1):
                raise GeoIPError('Invalid database type; region_* methods expect '\
                                 'Region or City database')
                
            return self._get_region(ipnum)
        except ValueError:
            raise GeoIPError('*_by_addr methods only accept IP addresses. Use *_by_name for hostnames. (Address: %s)' % addr)
            
    def region_by_name(self, hostname):
        """
        Lookup the region for given hostname.
        Use this method if you have a Region database.
        
        @param hostname: host name
        @type hostname: str
        @return: dict containing country_code, region,
            and region_name
        @rtype: dict
        """
        addr = socket.gethostbyname(hostname)
        return self.region_by_addr(addr)
    