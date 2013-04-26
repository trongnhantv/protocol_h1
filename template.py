#!/usr/bin/python

#  Copyright (c) 2013 Charles V Wright <cvwright@cs.pdx.edu>
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The names of the authors and copyright holders may not be used to
#     endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
#  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
import sys
import time
import heapq
import random

from multiprocessing import Process, Queue
from Queue import Full as QueueFullException

from optparse import OptionParser

import dpkt


DEBUG = False


def get_packet(g):
  packet = None
  try:
    packet = g.next()
  except StopIteration:
    packet = None
  return packet


def run_output_interface(iface_num, q, trans_delay):
  filename = "output-%d.pcap" % iface_num
  f = open(filename, "wb")
  writer = dpkt.pcap.Writer(f)
  while True:
    p = q.get()
    if p is None: 
      writer.close()
      f.close()
      break
    ts, pkt = p
    time.sleep(trans_delay)
    writer.writepkt(pkt, ts+trans_delay)


def callback(ts, pkt, iface, queues):
  ##
  ##
  ##       YOUR CODE GOES HERE
  ##
  ##
  pass    # 'pass' is Python for 'do nothing'


if __name__ == "__main__":

  # Seed the random number generator
  random.seed()

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-n", "--num-interfaces", dest="n", help="number of interfaces", default="4")
  parser.add_option("-t", "--table-size", dest="t", help="size of MAC address table", default="10")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()

  num_interfaces = int(options.n)
  MAC_tbl_size = int(options.t)
  DEBUG = options.debug

  # First, initialize our inputs
  generators = {}
  input_files = {}
  for i in range(1,num_interfaces+1):
    f = open("input-%d.pcap" % i, "r")
    input_files[i] = f
    reader = dpkt.pcap.Reader(f)
    generator = reader.__iter__()
    generators[i] = generator

  # Initialize our output interfaces
  output_queues = {}
  output_interfaces = {}
  transmission_delay = 0.10
  for i in range(1,num_interfaces+1):
    output_queues[i] = Queue(10)
    output_interfaces[i] = Process(target=run_output_interface, args=(i, output_queues[i], transmission_delay))
    output_interfaces[i].start()

  # h is a heap-based priority queue containing the next available packet from each interface.
  h = []
  # We start out by loading the first packet from each interface into h.
  # We always use the heapq functions to access h; this way, we preserve the heap invariant.
  for iface in generators.keys():
    p = get_packet(generators[iface])
    if p is not None:
      ts, pkt = p
      heapq.heappush(h, (ts, pkt, iface))

  # Now we're ready to iterate over all the packets from all the input files.
  # By using the heapq functions, we guarantee that we process the packets in 
  # the order of their arrival, even though they come from different input files.

  ts = 0.0            # We keep track of the current packet's timestamp
  prev_ts = 0.0       # And the previous packet's timestamp

  # While there are packets left to process, process them!
  while len(h) > 0:
    # Pop the next packet off the heap
    p = heapq.heappop(h)
    # Unwrap the tuple.  The heap contains triples of (timestamp, packet contents, interface number)
    ts, pkt, iface = p
    if DEBUG:
      print "Next packet is from interface %d" % iface

    # Inject some additional delay here to simulate processing in real time
    interarrival_time = ts-prev_ts
    if DEBUG:
      print "Main driver process sleeping for %1.3fs" % interarrival_time
    time.sleep(interarrival_time)
    prev_ts = ts

    # Call our callback function to handle the input packet
    callback(ts, pkt, iface, output_queues)

    p = get_packet(generators[iface])
    if p is not None:
      # The individual input generators provide us with timestamps and packet contents
      ts, pkt = p
      # We augment this data with the number of the input interface before putting it into the heap
      # The input iface number will be helpful in deciding where to send the packet in callback()
      heapq.heappush(h, (ts, pkt, iface))
    else:
      if DEBUG:
        print "Interface %d has no more packets" % iface

  # Now that we're done reading, we can close all of our input files.
  for i in input_files.keys():
    input_files[i].close()

  # We also let our output interfaces know that it's time to shut down
  for i in output_queues.keys():
    output_queues[i].put(None)
  # And we wait for the output interfaces to finish writing their packets to their pcap files
  for i in output_interfaces.keys():
    output_interfaces[i].join()


