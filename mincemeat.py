#!/usr/bin/python

import asynchat
import asyncore
import cPickle as pickle
import datetime
import hashlib
import hmac
import json
import logging
import marshal
import optparse
import os
import socket
import threading
import time
import types

VERSION = 0.0


logging.basicConfig(level=logging.DEBUG)
DEFAULT_PORT = 11235


class Protocol(asynchat.async_chat):
    def __init__(self, conn=None):
        if conn:
            asynchat.async_chat.__init__(self, conn)
        else:
            asynchat.async_chat.__init__(self)

        self.set_terminator("\n")
        self.buffer = []
        self.auth = None
        self.mid_command = False

    def collect_incoming_data(self, data):
        self.buffer.append(data)

    def send_command(self, command, data=None):
        if data:
            pdata = pickle.dumps(data)
            command['data-length'] = len(pdata)
            logging.debug( "<- %s + %d" % (json.dumps(command), len(pdata)))
            self.push(json.dumps(command) + "\n" + pdata)
        else:
            logging.debug( "<- %s" % json.dumps(command))
            self.push(json.dumps(command) + "\n")

    def found_terminator(self):
        if not self.mid_command:
            logging.debug("-> %s" % ''.join(self.buffer))
            command = json.loads(''.join(self.buffer))
            if 'data-length' in command:
                self.set_terminator(command['data-length'])
                self.mid_command = command
            else:
                self.process_command(command)
        else: # Read the data segment from the previous command
            data = pickle.loads(''.join(self.buffer))
            self.set_terminator("\n")
            command = self.mid_command
            self.mid_command = None
            if not self.auth == "Done":
                logger.fatal("Recieved pickled data from unauthed source")
                sys.exit(1)
            self.process_command(command, data)
        self.buffer = []

    def send_challenge(self):
        self.auth = os.urandom(20).encode("hex")
        self.send_command({"action": "challenge", "msg": self.auth})

    def respond_to_challenge(self, command, data):
        mac = hmac.new(self.password, command["msg"], hashlib.sha1)
        self.send_command({"action": "auth", "mac": mac.digest().encode("hex")})
        self.post_auth_init()

    def verify_auth(self, command, data):
        mac = hmac.new(self.password, self.auth, hashlib.sha1)
        if command["mac"] == mac.digest().encode("hex"):
            self.auth = "Done"
            logging.info("Authorized other end")
        else:
            self.handle_close()

    def process_command(self, command, data=None):
        commands = {
            'challenge': self.respond_to_challenge,
            'auth': self.verify_auth,
            'disconnect': lambda x, y: self.handle_close(),
            }

        if command["action"] in commands:
            commands[command["action"]](command, data)
        else:
            logging.critical("Unknown command received: %s" % (command["action"],)) 
            self.handle_close()
        

class Client(Protocol):
    def __init__(self):
        Protocol.__init__(self)
        self.mapfn = self.reducefn = self.collectfn = None
        
    def conn(self, server, port):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((server, port))
        asyncore.loop()

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def set_mapfn(self, command, mapfn):
        self.mapfn = types.FunctionType(marshal.loads(mapfn), globals(), 'mapfn')

    def set_collectfn(self, command, collectfn):
        self.collectfn = types.FunctionType(marshal.loads(collectfn), globals(), 'collectfn')

    def set_reducefn(self, command, reducefn):
        self.reducefn = types.FunctionType(marshal.loads(reducefn), globals(), 'reducefn')

    def call_mapfn(self, command, data):
        results = {}
        for k, v in self.mapfn(command['mapid'], data):
            if k not in results:
                results[k] = []
            results[k].append(v)
        if self.collectfn:
            for k in results:
                results[k] = [self.collectfn(k, results[k])]
        self.send_command({'action':'mapdone', 'mapid':command['mapid']}, results)

    def call_reducefn(self, command, data):
        results = self.reducefn(command['reduceid'], data)
        self.send_command({'action':'reducedone','reduceid':command['reduceid']}, results)
        
    def ping(self, command, data):
        self.send_command({'action':'pong'})

    def process_command(self, command, data=None):
        commands = {
            'mapfn': self.set_mapfn,
            'collectfn': self.set_collectfn,
            'reducefn': self.set_reducefn,
            'map': self.call_mapfn,
            'reduce': self.call_reducefn,
            'ping': self.ping,
            }

        if command["action"] in commands:
            commands[command["action"]](command, data)
        else:
            Protocol.process_command(self, command, data)

    def post_auth_init(self):
        if not self.auth:
            self.send_challenge()


class Server(asyncore.dispatcher, object):
    def __init__(self):
        asyncore.dispatcher.__init__(self)
        self.mapfn = None
        self.reducefn = None
        self.collectfn = None
        self.datasource = None
        self.password = None

    def run_server(self, password, port=DEFAULT_PORT):
        self.password = password
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(("", port))
        self.listen(1)
        asyncore.loop()
        return self.taskmanager.results

    def handle_accept(self):
        conn, addr = self.accept()
        sc = ServerChannel(conn, self)
        sc.password = self.password

    def handle_close(self):
        self.close()

    def set_datasource(self, ds):
        self._datasource = ds
        self.taskmanager = TaskManager(self._datasource, self)
    
    def get_datasource(self):
        return self._datasource

    datasource = property(get_datasource, set_datasource)


class ServerChannel(Protocol):
    def __init__(self, conn, server):
        Protocol.__init__(self, conn)
        self.server = server

        self.start_auth()

    def handle_close(self):
        self.close()

    def start_auth(self):
        self.send_challenge()

    def start_new_task(self):
        command, data = self.server.taskmanager.next_task()
        self.send_command(command, data)

    def pong(self, command, data):
        self.last_pong = datetime.datetime.now()

    def map_done(self, command, data):
        self.server.taskmanager.map_done(command, data)
        self.start_new_task()

    def reduce_done(self, command, data):
        self.server.taskmanager.reduce_done(command, data)
        self.start_new_task()

    def process_command(self, command, data=None):
        commands = {
            'pong': self.pong,
            'mapdone': self.map_done,
            'reducedone': self.reduce_done,
            }

        if command["action"] in commands:
            commands[command["action"]](command, data)
        else:
            Protocol.process_command(self, command, data)

    def ping_pong(self):
        self.last_pong = datetime.datetime.now()
        while True:
            time.sleep(60)
            if self.last_pong + datetime.timedelta(seconds=80) < datetime.datetime.now():
                logging.info("timeout")
                self.handle_close()
                break
            self.send_command({'action':'ping'})

    def post_auth_init(self):
        self.ping_pong_thread = threading.Thread(target=self.ping_pong)
        self.ping_pong_thread.daemon = True
        self.ping_pong_thread.start()
        if self.server.mapfn:
            self.send_command({'action':'mapfn'}, marshal.dumps(self.server.mapfn.func_code))
        if self.server.reducefn:
            self.send_command({'action':'reducefn'}, marshal.dumps(self.server.reducefn.func_code))
        if self.server.collectfn:
            self.send_command({'action':'collectfn'}, marshal.dumps(self.server.collectfn.func_code))
        self.start_new_task()
    
class TaskManager():
    START = 0
    MAPPING = 1
    REDUCING = 2
    FINISHED = 3

    def __init__(self, datasource, server):
        self.datasource = datasource
        self.server = server
        self.state = TaskManager.START

    def next_task(self):
        #TODO: Make the state changes threadsafe
        if self.state == TaskManager.START:
            self.map_iter = self.datasource.iteritems()
            self.map_results = {}
            self.state = TaskManager.MAPPING
        if self.state == TaskManager.MAPPING:
            try:
                map_item = self.map_iter.next()
                return ({'action':'map', 'mapid':map_item[0]}, map_item[1])
            except StopIteration:
                self.state = TaskManager.REDUCING
                self.reduce_iter = self.map_results.iteritems()
                self.results = {}
            pass
        if self.state == TaskManager.REDUCING:
            try:
                reduce_item = self.reduce_iter.next()
                return ({'action':'reduce', 'reduceid':reduce_item[0]}, reduce_item[1])
            except StopIteration:
                self.state = TaskManager.FINISHED
            pass
        if self.state == TaskManager.FINISHED:
            self.server.handle_close()
            return ({'action':'disconnect'}, None)
    
    def map_done(self, command, data):
        for (key, values) in data.iteritems():
            if key not in self.map_results:
                self.map_results[key] = []
            self.map_results[key].extend(values)
                                
    def reduce_done(self, command, data):
        self.results[command['reduceid']] = data

def run_client():
    parser = optparse.OptionParser(usage="%prog [options]", version="%%prog %s"%VERSION)
    parser.add_option("-p", "--password", dest="password", help="password")
    parser.add_option("-P", "--port", dest="port", type="int", default=DEFAULT_PORT, help="port")
    #TODO: add -v option for verbose

    (options, args) = parser.parse_args()

    client = Client()
    client.password = options.password
    client.conn(args[0], options.port)
                      

if __name__ == '__main__':
    run_client()
