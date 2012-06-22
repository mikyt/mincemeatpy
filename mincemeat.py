#!/usr/bin/env python


################################################################################
# Copyright (c) 2010 Michael Fairley
# Copyright (c) 2012 Michele Tartara
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################

import asynchat
import asyncore
import cPickle as pickle
import hashlib
import hmac
import logging
import marshal
import optparse
import os
import random
import socket
import sys
import types
import time
import threading

VERSION = 0.1


DEFAULT_PORT = 11235

logger = logging.getLogger(__name__)

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
        self.password = ""

    def collect_incoming_data(self, data):
        self.buffer.append(data)

    def send_command(self, command, data=None):
        if not ":" in command:
            command += ":"
        if data:
            pdata = pickle.dumps(data)
            command += str(len(pdata))
            logging.debug( "<- %s" % command)
            self.push(command + "\n" + pdata)
        else:
            logging.debug( "<- %s" % command)
            self.push(command + "\n")

    def found_terminator(self):
        if not self.auth == "Done":
            command, data = (''.join(self.buffer).split(":",1))
            self.process_unauthed_command(command, data)
        elif not self.mid_command:
            logging.debug("-> %s" % ''.join(self.buffer))
            command, length = (''.join(self.buffer)).split(":", 1)
            if command == "challenge":
                self.process_command(command, length)
            elif length:
                self.set_terminator(int(length))
                self.mid_command = command
            else:
                self.process_command(command)
        else: # Read the data segment from the previous command
            if not self.auth == "Done":
                logging.fatal("Recieved pickled data from unauthed source")
                sys.exit(1)
            data = pickle.loads(''.join(self.buffer))
            self.set_terminator("\n")
            command = self.mid_command
            self.mid_command = None
            self.process_command(command, data)
        self.buffer = []

    def send_challenge(self):
        self.auth = os.urandom(20).encode("hex")
        self.send_command(":".join(["challenge", self.auth]))

    def respond_to_challenge(self, unused_command, data):
        mac = hmac.new(self.password, data, hashlib.sha1)
        self.send_command(":".join(["auth", mac.digest().encode("hex")]))
        self.post_auth_init()

    def post_auth_init(self):
        raise RuntimeError("Should be overridden by the subclass")
    
    def verify_auth(self, unused_command, data):
        mac = hmac.new(self.password, self.auth, hashlib.sha1)
        if data == mac.digest().encode("hex"):
            self.auth = "Done"
            logging.info("Authenticated other end")
        else:
            self.handle_close()

    def process_command(self, command, data=None):
        commands = {
            'challenge': self.respond_to_challenge,
            'disconnect': lambda unused_x, unused_y: self.handle_close(),
            }

        if command in commands:
            commands[command](command, data)
        else:
            logging.critical("Unknown command received: %s" % (command,)) 
            self.handle_close()

    def process_unauthed_command(self, command, data=None):
        commands = {
            'challenge': self.respond_to_challenge,
            'auth': self.verify_auth,
            'disconnect': lambda unused_x, unused_y: self.handle_close(),
            }

        if command in commands:
            commands[command](command, data)
        else:
            logging.critical("Unknown unauthed command received: %s" % (command,)) 
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

    def set_mapfn(self, unused_command, mapfn):
        self.mapfn = types.FunctionType(marshal.loads(mapfn), globals(), 'mapfn')

    def set_collectfn(self, unused_command, collectfn):
        self.collectfn = types.FunctionType(marshal.loads(collectfn), globals(), 'collectfn')

    def set_reducefn(self, unused_command, reducefn):
        self.reducefn = types.FunctionType(marshal.loads(reducefn), globals(), 'reducefn')

    def call_mapfn(self, unused_command, data):
        logging.info("Mapping %s" % str(data[0]))
        results = {}
        for k, v in self.mapfn(data[0], data[1]):
            if k not in results:
                results[k] = []
            results[k].append(v)
        if self.collectfn:
            for k in results:
                results[k] = [self.collectfn(k, results[k])]
        self.send_command('mapdone', (data[0], results))

    def wait(self, unused_command, unused_data):
        logging.debug("Waiting for 1 second")
        time.sleep(1)
        self.send_command('waitdone', None)
        
    def call_reducefn(self, unused_command, data):
        logging.info("Reducing %s" % str(data[0]))
        results = self.reducefn(data[0], data[1])
        self.send_command('reducedone', (data[0], results))
        
    def process_command(self, command, data=None):
        commands = {
            'mapfn': self.set_mapfn,
            'collectfn': self.set_collectfn,
            'reducefn': self.set_reducefn,
            'map': self.call_mapfn,
            'reduce': self.call_reducefn,
            'wait': self.wait
            }

        if command in commands:
            commands[command](command, data)
        else:
            Protocol.process_command(self, command, data)

    def post_auth_init(self):
        if not self.auth:
            self.send_challenge()
            

class Server(threading.Thread, asyncore.dispatcher, object):
    """MapReduce server

It can be instantiated this way
s = mincemeat.Server(password="changeme") 
s.mapfn = mapfn
s.reducefn = reducefn
s.start()

results = s.process_datasource(datasource)

Attributes:
    mapfn: The map function (must be pickle-able)
    reducefn: The reduce function (must be pickle-able)
    relaunch_map: Launch multiple copies of mapping jobs if there are 
                  idle workers (default: True)
    relaunch_reduce: Launch multiple copies of mapping jobs if there are 
                     idle workers (default: True)
    daemon: Like the daemon parameter of the threading.Thread object
            (default: True)
    initialized: is the server completely initialized and bound to the TCP port?
"""
    def __init__(self, password="", port=DEFAULT_PORT):
        threading.Thread.__init__(self)
        asyncore.dispatcher.__init__(self)
        self.mapfn = None
        self.reducefn = None
        self.collectfn = None
        self.datasource = None
        self.password = password
        self.port = port
        self.daemon = True # When the main thread is closed, 
                           # the server terminates too
        self.relaunch_map = True
        self.relaunch_reduce = True
        
        self.initialized = False
        
        self.taskmanager = TaskManager(self)
        
        
    def __del__(self):
        self.close()
    
    def initializing(self):
        return self.isAlive() and not self.initialized
        
    def run(self):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        try:
            self.bind(("", self.port))
            self.listen(1)
            self.initialized = True
            asyncore.loop()
        except:
            logger.exception("MapReduce Server ERROR")
        finally:
            self.close()

        
    def handle_accept(self):
        conn, addr = self.accept()
        sc = ServerChannel(conn, self)
        sc.password = self.password

    def handle_close(self):
        self.close()

    def process_datasource(self, ds):
        self._datasource = ds
        if ds is None:
            return
        
        data_processed = threading.Event()
        self.taskmanager.process_datasource(self._datasource, data_processed, self.relaunch_map, self.relaunch_reduce)
        data_processed.wait()
        
        return self.taskmanager.results
        
    def get_datasource(self):
        return self._datasource

    def close(self):
        if hasattr(self, "taskmanager") and self.taskmanager is not None:
            self.taskmanager.close()
        asyncore.dispatcher.close(self)
        
    datasource = property(get_datasource, process_datasource)


class ServerChannel(Protocol):
    _last_command = None
    _last_command_data = None
    
    def __init__(self, conn, server):
        Protocol.__init__(self, conn)
        self.server = server

        self.start_auth()

    def handle_close(self):
        """Handle disconnection of a client"""
        logging.info("Client disconnected")
        
        if (self._last_command is not None and
	   self._last_command != "disconnect"):
            #The client did not disconnect as a result of a shutdown request
            #Something went wrong
            #Put the job back on the list
            if self._last_command == 'map':
                self.server.taskmanager.redo_map(self._last_command_data)
            elif self._last_command == 'reduce':
                self.server.taskmanager.redo_reduce(self._last_command_data)
            else:
                #Should never arrive here
                print self._last_command
                assert(False)

        self.close()

    def start_auth(self):
        self.send_challenge()

    def save_as_last_sent(self, command, data):
        """Save the given command as the last sent"""
        self._last_command = command
        self._last_command_data = data
        
    def start_new_task(self):
        command, data = self.server.taskmanager.next_task()
        if command == None:
            return
        self.save_as_last_sent(command, data)
        self.send_command(command, data)

    def map_done(self, unused_command, data):
        self.server.taskmanager.map_done(data)
        self.start_new_task()

    def reduce_done(self, unused_command, data):
        self.server.taskmanager.reduce_done(data)
        self.start_new_task()

    def wait_done(self, unused_command, unused_data):
        self.start_new_task()
        
    def process_command(self, command, data=None):
        commands = {
            'mapdone': self.map_done,
            'reducedone': self.reduce_done,
            'waitdone': self.wait_done
            }

        if command in commands:
            commands[command](command, data)
        else:
            Protocol.process_command(self, command, data)

    def post_auth_init(self):
        if self.server.mapfn:
            self.send_command('mapfn', marshal.dumps(self.server.mapfn.func_code))
        if self.server.reducefn:
            self.send_command('reducefn', marshal.dumps(self.server.reducefn.func_code))
        if self.server.collectfn:
            self.send_command('collectfn', marshal.dumps(self.server.collectfn.func_code))
        self.start_new_task()
    
class TaskManager:
    START = 0
    MAPPING = 1
    REDUCING = 2
    WAITING = 3
    FINISHED = 4

    def __init__(self, server):
        self.server = server
        self.state = TaskManager.WAITING
        self.datasource = None

    def process_datasource(self, datasource, data_processed_event, relaunch_map=True, relaunch_reduce=True):
        self.datasource = datasource
        self.data_processed_event = data_processed_event
        self.relaunch_map = relaunch_map
        self.relaunch_reduce = relaunch_reduce
        self.state = TaskManager.START
    
    def next_task(self):
        def map_command(map_key, map_data):
            """Add the computation to the working maps and return the 
               map command"""
            map_item = map_key, map_data
            self.working_maps[map_item[0]] = map_item[1]
            return ('map', map_item)
        
        # Body of the function
        if self.state == TaskManager.START:
            self.map_iter = iter(self.datasource)
            self.working_maps = {}
            self.map_results = {}
            self.redo_maps = {}
            self.redo_reduces = {}
            #self.waiting_for_maps = []
            self.state = TaskManager.MAPPING
        if self.state == TaskManager.MAPPING:
            try:
                map_key = self.map_iter.next()
                map_data = self.datasource[map_key]
                return map_command(map_key, map_data)
            except StopIteration:
                if len(self.redo_maps) > 0:
                    #Relaunch failed computations
                    key = random.choice(self.redo_maps.keys())
                    data = self.redo_maps[key]
                    del self.redo_maps[key]
                    return map_command(key, data)
                if len(self.working_maps) > 0:
                    if self.relaunch_map:
                        #Relaunch the remaining computations multiple times
                        key = random.choice(self.working_maps.keys())
                        return ('map', (key, self.working_maps[key]))
                    else:
                        #Nothing to do: just wait for the other computations
                        return ('wait', None)
                #Else: all mapping done
                self.state = TaskManager.REDUCING
                self.reduce_iter = self.map_results.iteritems()
                self.working_reduces = {}
                self.results = {}
        if self.state == TaskManager.REDUCING:
            try:
                reduce_item = self.reduce_iter.next()
                self.working_reduces[reduce_item[0]] = reduce_item[1]
                return ('reduce', reduce_item)
            except StopIteration:
                if len(self.redo_reduces) > 0:
                    #Relaunch failed computations
                    key = random.choice(self.redo_reduces.keys())
                    data = self.redo_reduces[key]
                    del self.redo_reduces[key]
                    self.working_reduces[key] = data
                    return ('reduce', (key, data))
                if len(self.working_reduces) > 0:
                    if self.relaunch_reduce:
                        key = random.choice(self.working_reduces.keys())
                        return ('reduce', (key, self.working_reduces[key]))
                    else:
                        return ('wait', None)
                #Else: all reductions done
                self.state = TaskManager.WAITING
                self.data_processed_event.set()
        if self.state == TaskManager.WAITING:
            return ('wait', None)
        if self.state == TaskManager.FINISHED:
            self.server.handle_close()
            return ('disconnect', None)

    
    def redo_map(self, map_item):
        """A client has failed during a map. Put the data back so that the job
can be done again"""
        map_key, map_data = map_item
        
        #This computation is not a working one anymore
        del self.working_maps[map_key]
        
        #But it is waiting to be redone
        self.redo_maps[map_key] = map_data
        
        
    def redo_reduce(self, reduce_item):
        """A client has failed during a reduce. Put the data back so that the 
job can be done again"""
        reduce_key, reduce_data = reduce_item
        
        #This computation is not a working one anymore
        del self.working_reduces[reduce_key]
        
        #But it is waiting to be redone
        self.redo_reduces[reduce_key] = reduce_data
        
        
    def map_done(self, data):
        # Don't use the results if they've already been counted
        if not data[0] in self.working_maps:
            return

        for (key, values) in data[1].iteritems():
            if key not in self.map_results:
                self.map_results[key] = []
            self.map_results[key].extend(values)
        del self.working_maps[data[0]]
                                
    def reduce_done(self, data):
        # Don't use the results if they've already been counted
        if not data[0] in self.working_reduces:
            return
        logging.debug("Finished reduce: %s", data[0])
        self.results[data[0]] = data[1]
        del self.working_reduces[data[0]]
        
    def close(self):
        self.state = TaskManager.FINISHED
        

def run_client():
    parser = optparse.OptionParser(usage="%prog [options]", version="%%prog %s"%VERSION)
    parser.add_option("-p", "--password", dest="password", default="", help="password")
    parser.add_option("-P", "--port", dest="port", type="int", default=DEFAULT_PORT, help="port")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
    parser.add_option("-V", "--loud", dest="loud", action="store_true")

    (options, args) = parser.parse_args()
                      
    if options.verbose:
        logging.basicConfig(level=logging.INFO)
    if options.loud:
        logging.basicConfig(level=logging.DEBUG)

    client = Client()
    client.password = options.password
    client.conn(args[0], options.port)
                      

if __name__ == '__main__':
    run_client()
