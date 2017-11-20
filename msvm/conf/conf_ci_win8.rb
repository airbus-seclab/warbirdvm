#!/usr/bin/env ruby
# encoding: ASCII-8BIT

#
#  This file is part of warbirdvm/msvm and is released under GPLv2 (see warbirdvm/COPYING)
#  Copyright Airbus
#

# ci.dll, 6.2.9200.16384 (win8_rtm.120725-1247) addresses
HANDLER_BASE64 = 0x8007EAC0
HANDLER_INDEX_MASK = 0x7ff
SCRAMBLER_ADDR = 0x80077C84
SESSION_ALLOC  = nil
TBOX_TABLE =     0x8007B080
CPUCACHEFILE = 'proc.txt'

