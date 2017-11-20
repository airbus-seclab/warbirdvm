#!/usr/bin/env ruby
# encoding: ASCII-8BIT

#
#  This file is part of warbirdvm/msvm and is released under GPLv2 (see warbirdvm/COPYING)
#  Copyright Airbus
#

# peauth.sys, 6.2.9200.16384 (win8_rtm.120725-1247) addresses
HANDLER_BASE64 = 0x000C6230
HANDLER_INDEX_MASK = 0xfff
SCRAMBLER_ADDR = 0x000B4FF4
SESSION_ALLOC =  0x000328FC
TBOX_TABLE =     0xc25f0
CPUCACHEFILE = 'proc_peauth.txt'
