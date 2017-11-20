#!/usr/bin/env ruby
# encoding: ASCII-8BIT

#
#  This file is part of warbirdvm/msvm and is released under GPLv2 (see warbirdvm/COPYING)
#  Copyright Airbus
#

require 'metasm'
require 'msvm64'

include Metasm

exename = 'ci.win8.dll'
msvm = Msvm.new(exename)

initStore_default_ctx = {
  :rdi => 0xFAF1D7C599A70ADD,
  :rax => 0xFAF1D7C599A70ADD,
  :rbx => 0xA00000,
  :ctx_5 => 0x66666666, #:ketickcount,
  :ctx_8 => 0xC000000000, # store pointer
  :ctx_f => 0xA00000, # stack pointer
  :ctx_12 => 0xC31C4F59A8645793,
  :ctx_27 => 0xFF9CAA0499D6ACBE,
  :ctx_31  => 0xA00000, # init
  :ctx_37 => 0x0,

  Indirection[0xA00000, 8, nil] => 0
}

msvm.exec('initStore', initStore_default_ctx)
