# encoding: ASCII-8BIT

#
#  This file is part of warbirdvm/msvm and is released under GPLv2 (see warbirdvm/COPYING)
#  Copyright Airbus
#

class Msvm

  attr_accessor :disasm

  NREGS = 0x40
  XOR_CONST_HADDR = 0xC0DEC0DEC0DEC0DE

  VMLOGFILE = 'log.txt'
  CTXCACHEFILE = 'ctx.txt'

  $DEBUG_ALL = false
  $DEBUG_SINGLE_STEP = false | $DEBUG_ALL
  $DEBUG_EVAL_BD     = false | $DEBUG_ALL
  $DEBUG_SOLVE_BD    = false | $DEBUG_ALL
  $DEBUG_INJECTOR    = false | $DEBUG_ALL

  def initialize(exename, conf_file = 'ci_win8')
    @d = AutoExe.decode_file(exename).init_disassembler
    # need to increase original values to support large handlers
    @d.disassemble_maxblocklength = 600
    @d.backtrace_maxcomplexity = 8000
    #@d.debug_backtrace = true

    @curfunc = ''
    @nhandler = 0
    @handler_binding = {}

    # load appropriate configuration file
    case conf_file
    when 'ci_win8' then  require 'conf/conf_ci_win8'
    when 'peauth_win8' then require 'conf/conf_peauth_win8'
    else  require 'conf/conf_ci_win8'
    end

    # init symbolic binding with native and virtual registers
    @symbolic_vm = {}
    [4,8].each{|size| @symbolic_vm[Indirection[Expression[:rcx], size, nil]] = Expression["ctx_0".to_sym]}
    # add alias for operand size < 4
    [1,2,3].each{|j| @symbolic_vm[Indirection[Expression[:rcx, :+, j], 1, nil]] = Expression[["ctx_0".to_sym, :>>, j*8], :&, 0xFF]}

    (NREGS-1).times{|i|
      [4,8].each{|size| @symbolic_vm[Indirection[Expression[:rcx, :+, (i+1)*8], size, nil]] = Expression["ctx_#{(i+1).to_s(16)}".to_sym]}
      # add alias for operand size < 4
      [1,2,3].each{|j| @symbolic_vm[Indirection[Expression[:rcx, :+, (i+1)*8+j], 1, nil]] = Expression[["ctx_#{(i+1).to_s(16)}".to_sym, :>>, j*8], :&, 0xFF]}
    }

    # init dummy context with virtual and native registers
    @ctx = {}
    NREGS.times{|i| @ctx["ctx_#{(i).to_s(16)}".to_sym] = 0}
    @ctx[:TBOX_TABLE] =  TBOX_TABLE
    @d.cpu.register_symbols.each{|reg| @ctx[reg] = reg}

    # set constraints on the environment
    Expression.reduce_lambda = lambda { |e|
      next e if not e.kind_of? Expression

      # store and res_out pointers are always valid
      if  (e.lexpr == :store_ptr and e.op == :'!=' and e.rexpr == 0) or
      (e.lexpr == :res_out_ptr and e.op == :'!=' and e.rexpr == 0) or
      (e.lexpr == :store_ptr and e.op == :'!=' and e.rexpr == 0xffffffff_ffffffff) or
      (e.lexpr == :res_out_ptr and e.op == :'!=' and e.rexpr == 0xffffffff_ffffffff)

        1

      elsif (e.lexpr == :store_ptr and e.op == :'==' and e.rexpr == 0) or
      (e.lexpr == :res_out_ptr and e.op == :'==' and e.rexpr == 0)

        0

      else
        e
      end
    }

    # shortcut scrambling function disassembling
    [[SCRAMBLER_ADDR, 'vm_ctx_scrambler']].each{|addr, name|
      @d.auto_label_at(addr, name)
      @d.decoded[addr] = true
      df = DecodedFunction.new
      df.btbind_callback = {:rsp => Expression[:rsp, :+, 8]}
      dummy_func = @d.function[:default].dup
      @d.cpu.register_symbols.each{|reg| dummy_func.backtrace_binding.delete(reg)}
      @d.function[addr] = dummy_func
    }

    # reload cached cpu (handlers' semantics)
    load_cpu()
  end

  def dump_cpu()
    File.open(CPUCACHEFILE, 'w'){|fd| @handler_binding.each{|haddr,bd|fd.puts "[0x#{haddr.to_s(16)},#{bd.inspect}]\n"} }
  end

  # dump protected store to file
  def dump_store()
    File.open('STORE.BIN', 'w'){|fd| (0x30/4).times{|i| fd << [@ctx[Indirection[0xc000000000+i*4, 4, nil]]].pack('L')}}
    log("[+] store has been dumped", true)
  end

  def dump_key()
    if (key = @ctx[Indirection[0x9fffd0, 8, nil]])
      File.open('KEY.BIN', 'w'){|fd| fd << [@ctx[Indirection[0x9fffd0, 8, nil]]].pack('Q')}
      log("[+] key has been dumped", true)
    else
      log("[+] can't find key in context", true)
    end
  end

  def load_handler(haddr, reduced)
    @handler_binding[reduced ? haddr : (haddr ^ XOR_CONST_HADDR)]
  end

  # load cpu (handlers' semantics) from file
  def load_cpu()
    return if not File.exists? CPUCACHEFILE
    File.open(CPUCACHEFILE, 'r').readlines.each{|line|
      haddr, raw_binding = eval(line)
      binding = sym_inject(raw_binding, @symbolic_vm)
      # puts " [+] load handler 0x#{haddr.to_s(16)}"
      @handler_binding[haddr] = binding
    }
    puts "[+] cpu reloaded from cache, #{@handler_binding.size} handler(s) have been loaded"
  end

  def cache_handler(haddr, bd, reduced)
    store_addr = reduced ? haddr : (haddr ^ XOR_CONST_HADDR)
    File.open(CPUCACHEFILE, 'a+'){|fd| fd.puts "[0x#{store_addr.to_s(16)},#{bd.inspect}]\n"}
    @handler_binding[store_addr] ||= bd
  end

  def ctx_cache_dir() "contexts_#{@curfunc}" end

  def ctx_cache_name(n) "./contexts_#{@curfunc}/ctx_#{"%05d" % n}.txt" end

  def load_context(n=nil)
    ctxfile = n ? ctx_cache_name(n) : CTXCACHEFILE
    return if not File.exists? ctxfile
    @ctx = eval(File.open(ctxfile, 'r').readlines.first)
    display(@ctx)
    puts "[+] context reloaded from cache"
  end

  def cache_context(n = nil)
    ctxfile = (n ? ctx_cache_name(n) : CTXCACHEFILE)
    File.open(ctxfile, 'w'){|fd| fd.puts "#{@ctx.inspect}"}
    puts "[+] context has been cached"
  end

  # exec: symbolic execution of the vm bytecode
  # params:
  #  - funcname: na
  #  - default: context used to init the vm
  #  - step: step index where to begin the symbolic execution
  def exec(funcname, default = nil, step = nil)
    File.unlink(VMLOGFILE) if File.exists? VMLOGFILE
    @nhandler += step if step
    @curfunc = funcname
    Dir.mkdir(ctx_cache_dir()) unless Dir.exists? ctx_cache_dir()
    default ? init_context(default) : load_context(step)
    while single_step(); end

    dump_cpu()
    puts "\n[+] Death on two legs !"
  end

  def init_context(default)
    @ctx.update default
    puts "[+] initial context"
    display(@ctx)
  end

  def extract_key()
    Expression[@ctx[:rax]].reduce_rec
  end

  def step_key()
    @ctx[:rdi] = extract_key()
    @ctx[:rax] = Expression[@ctx[:rdi], :&, HANDLER_INDEX_MASK].reduce_rec
    @ctx[:rdx] = @ctx[:rdi]
  end

  def handler_addr_from_ctx()
    @d.normalize(@d.decode_dword(HANDLER_BASE64 + @ctx[:rax]*8))
  end

  def single_step()
    vmkey = step_key()
    log("\n\n---------------------------------------", true)
    log("[+] (#{@nhandler.to_s(16)}) step with vmkey 0x#{vmkey.to_s(16)} \n", true)
    @nhandler+=1

    # extract handler's address from context
    haddr = handler_addr_from_ctx()

    # compute handler's binding
    bd = analyze_handler(haddr)

    # pure symbolic computation
    sym = sym_exec(bd, {:symbolic => true})

    # effective context update
    sym_exec(bd)

    vmkey = extract_key()
    vmkey = (vmkey.kind_of? Integer) ? vmkey : 0
    puts "[+] final vmkey 0x#{vmkey.to_s(16)}"

    cache_context(@nhandler)

    gets if $DEBUG_SINGLE_STEP
    (vmkey == 0) ? nil : true
  end

  # block_at: get InstructionBlock object at a given address
  def block_at(addr)
    return nil if not di = @d.di_at(@d.normalize(addr))
    di.block
  end

  # reach_ret: return handler's last block (contains a ret)
  def reach_ret(block, &func_callback)
    addr = block.list.first.address

    while true

      case instr = block.list.last.instruction.opname.to_s
      when /call/
        raise "[-] Unsupported call at Ox#{block.list.last.address}" if not block.to_subfuncret.size == 1

        if (block.to_normal.to_a.size == 1 and SESSION_ALLOC)
          pfn = @d.normalize(block.to_normal.to_a.first)
          case pfn
          when SESSION_ALLOC
            log("[+] allocation 0x#{Expression[@ctx[:rcx]]} bytes")
            @ctx[:rax] = 0xEE000000
            gets
          end
        else
          # scambling function emulation callback
          yield block.list.last.address
        end

        block.list.last.backtrace_binding = {}

        # get next block
        target_addr = @d.normalize(block.to_subfuncret.first)
        @d.disassemble_fast_deep(target_addr) if not @d.di_at(target_addr)
        block = block_at(target_addr)

      when /j/
        end_addr = block.list[-2].address
        jcc = block.list.last
        puts "[+] step block from #{addr.to_s(16)} to #{end_addr.to_s(16)}"

        opt = {:block_step => true, :finalize => true, :complex => true}
        block_bd = eval_binding(addr, end_addr, opt)
        block_bd = sym_exec(block_bd, opt)

        #        display(block_bd)
        log("[+] to_normal size #{block.to_normal.size}", true)

        # emulate conditional jump
        if (block.to_normal.size == 1)
          addr = @d.normalize(jcc.instruction.args.first)
          block = block_at(addr)
          log("[+] new target (1) 0x#{addr.to_s(16)}", true)

        elsif (block.to_normal.size == 2)

          puts @d.get_xrefs_x(block.list.last)

          # emulate condition
          if  (block.list[-2].instruction.opname.to_s == 'cmp')
            log("[+] emulate cmp instruction", true)
            op1, op2 = block.list[-2].instruction.args.collect{|op|  @ctx[op.to_s.sub('e', 'r').to_sym]}
            log("[+] operands values #{op1}, #{op2}", true)

            puts block.list[-2].instruction
            p op1
            p op1.to_s(16)
            p op2
            p op2.to_s(16)
            p instr

            cond = case instr
            when /jz/, /je/;
              op1 == op2
            when /jnz/, /jne/;
              op1 != op2
            when /jb/, /jnae/;
              op1 < op2
            when /jnbe/, /ja/;
              op1 > op2
            else
              raise "[-] Unsupported condition code"
            end

            log("[+] condition evaluates to #{cond}", true)

            addr = @d.normalize(cond ? jcc.instruction.args.first :  jcc.next_addr)
            block = block_at(addr)
            log("[+] new target (2) 0x#{addr.to_s(16)}", true)
            gets

          else
            puts block.list

            raise "[-] Unhandled instruction."
          end

          log("[+] new target 0x#{addr.to_s(16)}", true)
          gets
        end

      when /ret/
        break

      else
        puts block.list
        puts "[+] step block from #{addr.to_s(16)} to #{block.list.last.address.to_s(16)}"
        opt = {:block_step => true, :finalize => true, :complex => true}
        block_bd = eval_binding(addr, block.list.last.address, opt)
        block_bd = sym_exec(block_bd, opt)

        gets

        block = block_at(block.list.last.next_addr)
        #        raise "[-] If you put your mind to it, you can accomplish anything." if not(block.to_normal.size == 1)
      end
    end

    [addr, block]
  end

  # vm_ctx_scramble: emulate context registers scrambling function
  def vm_ctx_scramble(key, scamble_word, round)
    scrambling = {} # function's binding

    round.times{|i|
      scr = scamble_word[i]
      log("  [+] key 0x#{key.to_s(16)}", true)
      log("  [+] scramble word 0x#{scr.to_s(16)}", true)
      perm = scr ^ key

      log("  [+] permutations word 0x#{perm.to_s(16)}, #{[perm].pack('L').unpack('C*').map{|v| v.to_s(16)}}", true)

      index_a, index_b, index_c, index_d = [perm].pack('L').unpack('C*')
      key = (((key << 3) ^ (key >> 3)) + perm) & 0xffff_ffff

      log("  [+]  ctx_#{index_b.to_s(16)} = ctx_#{index_a.to_s(16)}", true)
      log("  [+]  ctx_#{index_d.to_s(16)} = ctx_#{index_c.to_s(16)}", true)

      scrambling["ctx_#{index_b.to_s(16)}".to_sym] = "ctx_#{index_a.to_s(16)}".to_sym
      scrambling["ctx_#{index_d.to_s(16)}".to_sym] = "ctx_#{index_c.to_s(16)}".to_sym
    }

    # emulate behavior of scrambling on context
    sym_exec(scrambling, {:scramble => true})
    puts "[+] sub-function done, go back to main context"
  end

  # analyze_handler: disasm and analyze an handler
  def analyze_handler(addr)
    addr = @d.normalize(addr)
    log("[+] analyzing handler 0x#{Expression[@ctx[:rax]].reduce_rec.to_s(16)} at 0x#{addr.to_s(16)}\n", true)

    @d.disassemble_fast_deep(addr) if not @d.di_at(addr)
    raise '[-] invalid handler address' if not (@d.di_at(addr) and block = @d.di_at(addr).block)

    addr, last_block = reach_ret(block){|end_addr|
      # callback for vm_ctx_scramble function emulation
      puts "[+] guessing func context, considering code to #{end_addr.to_s(16)}"
      opt = {:finalize => false}
      subbd = eval_binding(addr, end_addr, opt)
      subbd = sym_exec(subbd, opt)

      # compute local context at scrambling point, extract args
      args = Hash[[:src, :dest, :key].zip([:r8, :rcx, :rdx].map{|a| Expression[subbd[a]].reduce_rec})]
      args[:len] = args[:key] & 0xFF
      args.each{|k, v| puts "#{k} => #{Expression[v]}"}
      scamble_data = @d.read_raw_data(args[:src], args[:len]*4).unpack('L*')

      # apply scrambling to context
      vm_ctx_scramble(args[:key], scamble_data, args[:len])
    }

    # if handler is too complex (ie: more than two hundreds instructions), set a special flag
    threeshold = @d.di_at(addr).block.list.size > 200
    binding = eval_binding(addr, last_block.list.last.instruction, {:finalize => true, :complex => threeshold})
  end

  # inject_symbolism : inject symbolism hash into binding hash
  def sym_inject(binding, symbolism = @symbolic_vm)
    new_binding = {}
    binding.each{|k, val|
      k = Expression[k].bind(symbolism).reduce_rec
      val = Expression[val].bind(symbolism).reduce_rec
      new_binding[k] = val
    }
    new_binding
  end

  # sym_exec: symbolic execution
  # binding: binding that will be evaluated with respect to the current context
  # opt: options hash
  #     - symbolic: pure symbolic evaluation, all registers are reseted to symbols
  #     - debug: extensive step by step output
  #     - finalize: apply solved binding to current context if true
  def sym_exec(binding,  opt = {})
    return if not binding
    symbolic = (opt.has_key? :symbolic) ? opt[:symbolic] : false
    debug = opt.has_key? :debug
    scramble = opt.has_key? :scramble
    finalize = (opt.has_key? :finalize) ? opt[:finalize] : true

    if symbolic
      log("\n[+] enable symbolic semantic\n", true)
      # forge a pure semantic context
      tmp_ctx = @ctx.reject{|k,v| Expression[k].reduce_rec.kind_of? Indirection}
      NREGS.times{|i| r = "ctx_#{(i).to_s(16)}".to_sym; tmp_ctx[r] = r}
      @ctx.select{|k,v| Expression[v].reduce_rec == TBOX_TABLE}.each{|k,v| tmp_ctx[k] = :TBOX_TABLE}
      #[:rax, :rdx].each{|k| tmp_ctx[k] = @ctx[k]}

      # backup current register, exchange with semantic context
      backup_ctx = @ctx
      @ctx = tmp_ctx
    else
      log("\n[+] enable symbolic execution\n", true)
      debug = true if $DEBUG_INJECTOR
    end

    advbind = solve_binding(binding)

    if (not symbolic) and debug
      log("[+] solved binding", true)
      display(advbind, true)
    end

    advbind = sym_inject(advbind)

    if (not symbolic) and debug
      log("[+] symbolic solved binding", true)
      display(advbind, true)
    end

    # align_val lambda: solve size aliasing problem for hash value
    # byte ptr [0x1] => (dword ptr [0x0] >> 8) & 0xFF
    align_val = lambda{|exp|
      res = case exp
      when Expression
        exp.bind(exp.expr_indirections.inject({}){ |b, e| b.update e => Expression[align_val[e]] }).reduce

      when Indirection
        next exp if not (t = Expression[exp.target].reduce_rec)
        next exp if  not t.kind_of? Integer
        next exp if ((t & 1) == 0) or not exp.len == 1
        Expression[[Indirection[t-1, 4, exp.origin], :>>, 8], :&, 0xFF]
      else exp
      end

      res
    }

    # align_key lambda: solve size aliasing problem for hash key
    # find correct value from context and build mask
    align_key = lambda{|exp, val|
      next {exp => val} if not exp.kind_of? Indirection or not exp.len == 1
      next {exp => val} if not (t1 = Expression[exp.target].reduce_rec).kind_of? Integer

      aliasing = @ctx.select{|k|
        next false if exp == k
        next false if not (k.kind_of? Indirection and (t2 = Expression[k.target].reduce_rec).kind_of? Integer)
        (t1 & ((1 <<  64) - k.len)) == t2
      }

      next {exp => val} if not aliasing.size == 1
      k_alias, k_key = aliasing.to_a.first
      t2 = Expression[k_alias.target].reduce_rec
      mask = ((1 <<  64)-1) ^ (0xFF << (t1-t2)*8)
      {k_alias => Expression[[k_key, :&, mask], :|, val << (t1-t2)*8].reduce}
    }

    # injector lambda: iterative solver for keys and values in binding hash
    injector = lambda{|v, i, mode|
      next v if (v.kind_of? Symbol) and mode == :w
      next v if v.kind_of? Integer

      oldv = v
      oldoldv = oldv

      if $DEBUG_INJECTOR
        puts "\n\n\n-----------------------------------\n[+] injecting #{v} - mode #{mode}\n"
      end

      while true
        puts "1 #{Expression[v]}" if $DEBUG_INJECTOR
        # if key, do not solve final memory indirection
        break if (mode == :w) and v.kind_of? Indirection and Expression[v.target].reduce_rec.kind_of? Integer

        if mode == :r
          v = align_val[v]
          break if v.kind_of? Integer
        end
        puts "2 #{Expression[v]}" if $DEBUG_INJECTOR

        v = Expression[v].bind(@symbolic_vm).reduce_rec
        break if (v.kind_of? Symbol) and mode == :w
        puts "3 #{Expression[v]}" if $DEBUG_INJECTOR

        break if mode == :w and i[v]

        v = Expression[v].bind(i).reduce_rec
        break if (v.kind_of? Symbol) and mode == :w
        puts "4 #{Expression[v]}" if $DEBUG_INJECTOR

        v = Expression[solve_ind_partial(Expression[v], mode)].reduce_rec if (mode == :r)
        puts "5 #{Expression[v]}" if $DEBUG_INJECTOR
        puts "---------------------" if $DEBUG_INJECTOR

        raise "fuck infinite loop" if oldoldv == v and not oldoldv == oldv
        break if v == oldv
        oldoldv = oldv
        oldv = v
      end

      v
    }

    # expand binding
    exp_bd = expand_binding(advbind)

    # select keys that are not present in the current context
    # they may be used by the current (non-atomic) operation (binding)
    # should be ok, to focus on Indirection (local variables stored on the stack)
    non_atomic = exp_bd.select{|k,v| not @ctx.has_key? k and k.kind_of? Indirection}

    if (not symbolic) and debug
      puts "[+] non_atomic context"
      display(non_atomic)
    end

    # merge current context with non-atomic binding and expand to the whole context
    full_ctx = expand_binding(@ctx).merge(non_atomic)

    if (not symbolic) and debug
      puts "[+] full context"
      display(full_ctx)
    end

    # solve advanced binding using full (expanded) context
    full_bd = {}
    advbind.each{|key, val|
      full_key = (key.kind_of? Symbol) ? key : injector[key, full_ctx.reject{|k,v| k==key}, :w]
      full_val = injector[val, full_ctx.reject{|k,v| v==val}, :r]
      full_bd[full_key] = full_val
    }

    # remove expanded values from full_bd
    full_bd = expunge_binding(full_bd) if finalize

    if finalize and debug and (not symbolic)
      puts "[+] injected binding"
      display(full_bd)
    end

    # fix unaligned memory access
    final_bd = {}; full_bd.each{|k,v| final_bd.update(align_key[k,v])}

    if finalize and (not symbolic)
      log("[+] final binding", true)
      display(final_bd, true)
    end

    if symbolic
      # restore context
      @ctx = backup_ctx
      log("[+] step semantic", true)
      display(final_bd, true)
    else
      log("[+] updated context #{finalize ? "":"(simulation)"}-------------------", true)
      display(finalize ? @ctx.merge!(final_bd) : @ctx.merge(final_bd), true)
    end
  end

  # expunge_binding: reject registers bindings (except for rax and rbx) and local variables
  # as well as fake size aliased binding
  def expunge_binding(bd)
    bd.delete(:ip)
    bd.reject!{|k| k =~ /r/ and k != :rax and k != :rbx}
    bd.reject!{|k| k.kind_of? Indirection and k.origin == :size_aliasing }

    locals = bd.select{|expr| expr.to_s =~ /^(q|d)word ptr \[rsp/}
    var = locals.invert.keys.map{|e| Expression[e].reduce_rec}
    bd = bd.reject{|expr| var.include? expr or locals.has_key? expr}

    full_locals, final = expand_binding(locals), {}
    bd.each{|k,v| final[Expression[k].bind(full_locals).reduce_rec] = Expression[v].bind(full_locals).reduce_rec}
    final
  end

  # expand_binding: create byte, word and dword alias for qword ptr indirection
  def expand_binding(bd)
    expanded = bd.dup
    # a 'size_aliasing' tag is set in the origin field of the Indrection object
    bd.select{|k| k.kind_of? Indirection }.each{|k,v|[1,2,4].each{|i|
        next if k.len <= i # do not alias with equal or greater len/size
        expanded[Indirection[k.target, i, :size_aliasing]] = Expression[v, :&, (1 << (8*i))-1].reduce}}
    expanded
  end

  # eval_binding: compute symbolic binding
  # pure static computation, do not use context here
  #   addr: start address of the handler code
  #   end_addr: end address of the handler code
  #   opt: options hash
  #     - complex: extensive step by step output
  #     - finalize: clean binding (ex: remove local variables) if true
  def eval_binding(addr, end_addr, opt)
    complex = (opt.has_key? :complex) ? opt[:complex] : false
    finalize = (opt.has_key? :finalize) ? opt[:finalize] : true
    block_step = (opt.has_key? :block_step) ? opt[:block_step] : false

    if cachedbd = load_handler(addr, finalize)
      log("[+] cached handler binding", true)
      if $DEBUG_EVAL_BD
        display(cachedbd)
      end
      return sym_inject(cachedbd)
    end

    log("[+] new handler", true)
    log("[+] eval_binding #{addr.to_s(16)}, finalize:#{finalize}, complex:#{complex}", true)

    raw_binding = @d.code_binding(addr, end_addr)

    if $DEBUG_EVAL_BD
      log("[+] raw binding", true)
      display(raw_binding, true)
    end

    raw_binding = expunge_binding(raw_binding) if finalize and (not complex)

    # inject :rdx numerial value to make binding more compact
    raw_binding = solve_binding(raw_binding, {:rdx => @ctx[:rdx], :rax => @ctx[:rax]})

    if $DEBUG_EVAL_BD
      log("[+] raw binding - rdx injected", true)
      display(raw_binding, true)
    end

    cache_handler(addr, raw_binding, finalize) unless block_step

    if $DEBUG_EVAL_BD
      puts "[+] raw binding #{finalize ? '(without local variable)' : ''}"
      display(raw_binding)
    end

    binding = sym_inject(raw_binding)

    if $DEBUG_EVAL_BD
      puts "[+] symbolic handler binding"
      display(binding)
    end

    binding
  end

  def solve_binding(binding, ctx = nil)

    if ctx
      backup_ctx = @ctx
      @ctx = ctx
    end

    advbind = {}
    binding.each{|key, val|

      if $DEBUG_SOLVE_BD
        puts " key: #{key}\n val: #{Expression[val]}\n"
      end
      val = solve_expr(Expression[val], :r)

      if $DEBUG_SOLVE_BD
        puts " solved val: #{Expression[val]}\n"
        puts "\n--------------------\n\n"
      end

      # do not solve Symbol (ie: registers)
      if not Expression[key].reduce_rec.kind_of? Symbol
        key = Expression[Expression[key, :&, 0xffffffff_ffffffff]].reduce_rec
        key = solve_expr(Expression[key], :w)
      end

      advbind[key] = val
    }

    if ctx
      @ctx = backup_ctx
    end

    advbind
  end

  # solve_expr : solve an expression by contextualization
  # mode (r)ead or (w)rite for key or value
  def solve_expr(arg, mode = :r)
    bd = @ctx.dup
    bd.delete(:rcx) if not mode == :r

    arg_ctx = Expression[arg].bind(bd).reduce
    res = solve_ind_partial(arg_ctx, mode)

    if res.kind_of? Expression and res.op == :& and
    res.rexpr == 0xffffffff_ffffffff and res.lexpr.kind_of? Symbol
      res = res.lexpr
    end

    (res.kind_of? Integer)? Expression[res, :&, 0xffffffff_ffffffff].reduce: res
    res = Expression[res].reduce{|e| e.lexpr if e.kind_of? Expression and e.op == :& and e.rexpr == 0xffffffff_ffffffff}
    Expression[res].reduce_rec
  end

  # resolve (reduce) expressionss
  def solve_ind_partial(i, mode = :r)

    case (i =  Expression[i].reduce_rec)
    when Indirection
      # do not solve final Indirection when mode is w (key)
      return i if (mode == :w) and (i.complexity == 2)
      return i if (mode == :w) and Expression[i.target].reduce_rec.kind_of? Integer

      part = solve_ind_partial(i.target)

      if s = @d.get_section_at(part)
        return s[0].decode_imm("a#{i.len*8}".to_sym, @d.cpu.endianness)
      end

      Indirection[part, i.len, nil]

    when Expression
      i.bind(i.expr_indirections.inject({}) { |b, e| b.update e => Expression[solve_ind_partial(e, mode)] }).reduce

    when Fixnum; i
    when Integer; i
    when Symbol; i
    when :unknown; i
    else Expression::Unknown; raise i.inspect
    end
  end

  # puts wrapper that also log to file if output_verbose set to true
  def log(msg, output_verbose = false)
    puts msg if output_verbose
    File.open(VMLOGFILE, 'a+'){|fd| fd.puts msg}
  end

  # fancy format a hash, typically a binding or context
  # (tip: return displayed binding)
  # binding: hash to display
  # log_out: can be printed in log output
  def display(binding, log_out = false)
    return if not binding
    txtbd =  "\n"
    binding.each{|k, val|  txtbd += "#{Expression[k]} => #{Expression[val]}\n"}
    txtbd += "\n\n"
    log(txtbd) if log_out
    puts txtbd
    binding
  end

end
