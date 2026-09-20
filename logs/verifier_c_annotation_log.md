# `verifier.c` Annotation Log

**Prepared by:** Somnath
**Base file:** `verifier__1_.c` (clean kernel snapshot, `kernel/bpf/verifier.c`)
**Working file:** `verifier.c` (same file, with my own comments added on top)

## Scope and method

`verifier.c` was built directly on top of `verifier__1_.c` — I diffed the two files after stripping all comments and blank lines, and confirmed they are **byte-identical** underneath. Every difference between the two files is a comment I added; no logic was changed.

This document covers **only the functions where I actually added a comment.** Every other function in the file — including ones near the annotated functions, or ones that come up in passing in a comment — is deliberately left out, even where I could explain it, because the goal here is an accurate record of what I've *done*, not a general tour of the verifier.

For each function below: the exact comment(s) I wrote, in place, followed by a short expansion where the comment benefits from more context. Functions are listed in the order they appear in the file.

---

## 1. `check_map_access_type()`

```c
// checks the maps read/write capability flags
static int check_map_access_type(struct bpf_verifier_env *env, u32 regno,
                                 int off, int size, enum bpf_access_type type)
```

**What I wrote:** a one-line summary describing the function's purpose.

**Expansion:** this checks a map's `BPF_MAP_CAN_READ` / `BPF_MAP_CAN_WRITE` capability flags — a check that's independent of bounds-checking. A map can be marked read-only or write-only at creation time (e.g. via `map_flags`), and this function is what rejects an access that violates that, before any offset/size arithmetic is even considered.

---

## 2. `__check_mem_access()`

```c
static int __check_mem_access(struct bpf_verifier_env *env, int regno,
                              int off, int size, u32 mem_size,
                              bool zero_size_allowed)
```

**What I wrote**, inline in the body:
```c
// regno = register containing the pointer
// off = offset from the pointer
```

**Expansion:** just parameter-clarifying comments — no further logic annotated in this function yet.

---

## 3. `check_map_access()`

```c
static int check_map_access(struct bpf_verifier_env *env, u32 regno,
                            int off, int size, bool zero_size_allowed,
                            enum bpf_access_src src)
```

**What I wrote**, describing the two-stage structure of the function:
```c
// check_mem_region_access does the actual smin/umax bounds arithmetic
// if map has no record - btf_record describes special fields inside the value
// kptrs, spin locks, timers
// then plain arithmetic check which we have done so pass

// for each special field
// we need to check if access overlaps the offset stored in each of the struct
```

And, inside the per-field-type switch:
```c
case BPF_KPTR_UNREF: // unrefrenced kernel pointer
case BPF_KPTR_REF: // referenced kernel pointer
case BPF_KPTR_PERCPU:
        // if it is kptr(kernel pointer) stored inside a map value
        // it is dangerous to let the program touch
        // src can be either ACCESS_DIRECT or ACCESS_HELPER
        // if it is  ACCESS_HELPER then we reject it
        // it can only be called using the Direct Access Instructiions which are routed
        // through specialised check_map_kptr_access funciton
        // offset must be a known constant
        // verifier needs to know  exactly which byte is accessed
        //  so that it can be certain whether this is the corresponding field or not
        // it must start exactly at the beginning
        // access size must be exactly 8 bytes
default: // any other type like spin lock, timers, they are not accessible via load store,
        // they are checked using their corresponding helpers directly
```

**Expansion:** the function has two parts. First, `check_mem_region_access()` does the ordinary bounds check (`smin`/`umax` against the map's value size). Second, if the map's value type has a `btf_record` (meaning the struct stored in the map has "special fields" the kernel tracks — kernel pointers, spin locks, timers, etc.), every registered field is checked for **interval overlap** with the access being made (`[access_start, access_end) ∩ [field_start, field_end) ≠ ∅`).

For kernel-pointer fields specifically, the restrictions are tight for good reason:
- Only *direct* load/store instructions may touch a kptr field — access via a helper (`ACCESS_HELPER`) is rejected, because helpers are a generic path and can't be trusted to handle a raw kernel pointer safely.
- The offset must be a compile-time-known constant, so the verifier can be certain exactly which field is being touched.
- The access must start exactly at the field's beginning and be exactly 8 bytes — kptrs are pointer-sized; anything else (partial, misaligned) isn't a meaningful access to that field.

Every other special field type (spin locks, timers) can't be touched by load/store instructions at all — they're only manipulated via their own dedicated helper functions.

---

## 4. `check_mem_access()`

```c
static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno,
                            int off, int bpf_size, enum bpf_access_type t,
                            int value_regno, bool strict_alignment_once, bool is_ldsx)
```

**What I wrote** as the function's introductory comment:
```c
// check_mem_access() does three things
    // 1. convert size : converts bpf_size to bytes
    // 2. check alignment : ensure the access is properly aligned
    // 3. branch based on pointer type : diff pointer types have diff rules

/* types of pointers :
    1. PTR_TO_MAP_VALUE
    2. PTR_TO_STACK
    3. PTR_TO_CTX
    4. PTR_TO_PACKET
    5. PTR_TO_BTF_ID
*/
```

**On the `PTR_TO_MAP_KEY` branch:**
```c
// read only
// bounds : should be within map->key_size
// result : dest register becomes scalar value
```

**On the `PTR_TO_MAP_VALUE` branch:**
```c
// if this is a write operation and the value being written is itself a pointer
// then reject directly
// this is so that the user doesnt access the map value and then access that kernel address
// hence not allowed directly (info leak)

// checks the maps read/write capability flags
// BPF_MAP_CAN_READ or BPF_MAP_CAN_WRITE
// full bounds-plus-kptr-overlap check
// if the offset is a known constant, then it checks up whether the memory belongs to any
// registered kptr/uptr field in the map's BTF_RECORD
// if it is not known, kptr_field stays NULL
```
```c
// if the map is read only, we can read the contents of the map at verification time and store it as SCALAR_VALUE
```
```c
// if it is a jump table map, a read from one of these maps will produce a PTR_TO_INSN
// which will be used for the goto/indirect jump insn
```

**On the `PTR_TO_MEM` branch:**
```c
// pointer to chunk of memory of known size
bool rdonly_mem = type_is_rdonly_mem(reg->type); // is the memory read only?
bool rdonly_untrusted = rdonly_mem && (reg->type & PTR_UNTRUSTED); // is it both read only and UNTRUSTED

// null able pointers cannot be referenced
// if the register's type is still TYPE_MAYBE_NULL, then there was no proper check done before
// if type is read only, writes are rejected directly
```
```c
// cant write a kernel pointer in this memory region
```
```c
// If the pointer is untrusted (and read-only), skip the static bounds
// * proof entirely. There is no point proving the *offset* is in range
// * when the *base pointer itself* isn't guaranteed to point to live,
// * valid memory in the first place — offset-range arithmetic can't fix
// * that problem.
// Instead, this access is left type-tagged as PTR_UNTRUSTED here.
// * Later, in the post-verification fixup pass (convert_ctx_accesses()),
// * any load with this exact type combination gets its opcode rewritten
// * from an ordinary BPF_MEM load into a BPF_PROBE_MEM load. The JIT then
// * emits that as a real CPU instruction registered in the kernel's
// * exception table.
// At *runtime*, if the probe instruction faults on an invalid address,
// * the fault handler intercepts it (instead of crashing the kernel) and
// * redirects execution to a safe fallback — the destination register is
// * set to a failure value (e.g. 0) and execution continues normally.

// assuming we didnt hit any error
// (either the bounds check passed, or it was skipped because we're in the probe case)
// and this was a read, mark the destination register as an unknown scalar
// as we have no idea what it is
// it can be either the real data or the failed sentinal value that probe returned
```

**On the fallback/default branch:**
```c
// if we try to dereference an arbitrary scalar
```

**Expansion (of the `PTR_UNTRUSTED` probe-read comment specifically, since this is the most involved piece I wrote):** this is the mechanism that lets the verifier statically approve a dereference it *cannot* fully bounds-prove. If the base pointer itself isn't guaranteed valid, proving the offset is "in range" is meaningless — so instead of rejecting the access, the verifier tags it `PTR_UNTRUSTED` and defers the actual safety check to runtime: a later fixup pass rewrites the load into a `BPF_PROBE_MEM` instruction, which the JIT compiles into hardware that's registered in the kernel's exception table. If that instruction faults at runtime, the fault handler catches it, substitutes a safe default (typically 0) into the destination register, and execution continues — no kernel crash. This is why the destination register afterward is marked as an unknown scalar rather than anything more specific: from the verifier's point of view, the value could be the real data *or* the probe's failure sentinel, and it can't statically distinguish the two.

**Not yet annotated in this function:** the `PTR_TO_STACK` branch — this is explicitly the next thing on my list, per my study order (`check_mem_access` → `PTR_TO_STACK`, then `check_helper_call`, then `check_kfunc_call`, then `check_cond_jmp_op` + `is_branch_taken()`).

---

## 5. `check_helper_call()`

```c
// it validates calls to ebpf helper fucntions
// it checks that the arguments are correct, handles reference counting (acquire/release), processes callbacks, and sets up the return value.
// it is called from do_check_insn() when the instruction is a BPF_CALL with src_reg == 0 (indicating a helper function call).
// It also handles special cases for certain helpers that have specific argument requirements or return value constraints.
static int check_helper_call(struct bpf_verifier_env *env, struct bpf_insn *insn, int *insn_idx_p)
```

**What I wrote:** the function-level summary above — I have not yet gone through the body itself line-by-line. This is queued as the next major function after finishing `PTR_TO_STACK` in `check_mem_access`.

---

## 6. `check_alu_op()`

```c
if (opcode == BPF_END || opcode == BPF_NEG) {
```
**What I wrote**, immediately above this line:
```c
//BPF_END is the BPF instruction for byte swapping - converting betweeen little endian and big endian operations
```

**Expansion:** just this one opcode clarified so far; the rest of the function is unannotated.

---

## 7. `check_cond_jmp_op()`

```c
// predicts branch using helper func, forks state for taken and not taken branches, and refines register ranges based on the branch condition
static int check_cond_jmp_op(struct bpf_verifier_env *env, struct bpf_insn *insn, int *insn_idx)
```

Followed through most of the body:

```c
// BPF_JA are unconditional jumps
// conditional (may go to types) mainly for loops
```

```c
// register comparison, src_reg is a register
```
```c
if (src_reg->type == PTR_TO_STACK)
// immediate value comparison
```
```c
// always taken
```
```c
// push the other branch to the stack for further verification
// The other branch is the branch that is not taken, i.e., the false branch.

// reg_Set_min_max() is used to refine the min/max values of the registers based on the comparison operation.
// It takes the registers from both branches (true and false) and updates their min/max values accordingly.
```
```c
// this handles the case where multiple registers share the same ID, and we want to synchronize their states across branches.
// sync_linked_regs() is called to update the state of all registers that share the same ID as src_reg and dst_reg in both branches.
```
```c
// comparing a pointer that might be NULL with a pointer that is definitely not NULL.
```
```c
// You can't compare arbitrary pointers in BPF
```

**Expansion:** this covers branch prediction (`is_branch_taken()` returns whether the branch is always-taken, never-taken, or genuinely unknown), the actual state-forking logic (pushing the untaken branch onto the DFS stack when the outcome is unknown), range refinement in both branches after the comparison, and keeping linked/aliased scalar registers consistent via `sync_linked_regs()`. The final comment (arbitrary pointer comparison rejection) is a core soundness rule — the verifier can't reason about relationships between two independently-tracked pointers in general, so bare pointer-vs-pointer comparisons that don't fit a specific recognized pattern (null checks, packet-pointer matching) are rejected outright.

**Note:** the comment about `sync_linked_regs()`'s purpose is written at its *call site*, inside `check_cond_jmp_op` — I have not separately annotated `sync_linked_regs()`'s own function body.

**Not yet annotated:** `is_branch_taken()` itself — the actual prediction logic this function calls into. This is queued together with `check_kfunc_call()` as the next things after `check_helper_call`.

---

## 8. `visit_gotox_insn()`

```c
/* "conditional jump with N edges" */
static int visit_gotox_insn(int t, struct bpf_verifier_env *env)
```

**What I wrote:**
```c
// get or create jump table
// jump tabel is an array of all the possible target instruction indices
```

**Expansion:** this handles `gotox` — a computed/indirect jump via a jump table. The jump table (`env->insn_aux_data[t].jt`) lists every instruction index this jump could possibly land on; each valid target gets marked and pushed onto the DFS stack if not already visited.

---

## 9. `visit_abnormal_return_insn()`

```c
/*
 * Instructions that can abnormally return from a subprog (tail_call
 * upon success, ld_{abs,ind} upon load failure) have a hidden exit
 * that the verifier must account for.
 */
// in BPF some instructions can cause the program to exit unexpectedly
// withoug following the normal control flow
// like LD_ABS, LD_IND : packet access instrcutions
// if the packet is too small, jump to exit
// if succesful continue to the next instruction
// tail_call : another such abnormal : tail call instruction
//if the tail call succeeds, program exits ( jumps to another program )
// if the tail call fails continue to the next instruction
// so in this case, we add both the fall through and the exit as successors
static int visit_abnormal_return_insn(struct bpf_verifier_env *env, int t)
```

And inside the body:
```c
// jt is an array of succesor instruction indices
// if the instruciton already has a jump table we dont need to create another one

// else allocate the jump table - new struct bpf_iarray (contains int cnt, int items[])
```
```c
// bpf_find_containing_subprog finds which subpropgram the instruction at index
// t belongs to
// it uses binary search to find the subprogram
jt->items[0] = t + 1; // normal fall through
jt->items[1] = subprog->exit_idx; // abnormal exit
env->insn_aux_data[t].jt = jt; // store the jump tabel in the instrucitons auxillary data
// for later use
```

**Expansion:** some instructions can leave a subprogram without a visible jump in the bytecode: `LD_ABS`/`LD_IND` jump to the subprogram's exit if a packet-bounds check fails, and a tail call (`bpf_tail_call()`) that succeeds transfers control to an entirely different program. Since the CFG builder can't see these transitions directly in the instruction stream, this function manually registers both possible outcomes — the normal fall-through and the hidden exit — as CFG successors, so the graph stays sound.

---

## 10. `visit_insn()`

```c
/* Visits the instruction at index t and returns one of the following: ... */
```
Above the function:
```c
// this is called for each instr during the DFS traversal,
// it determines what type of instr. it is
// finds all possible successors
// pushes unvisited successors onto the stack
// returns whether exploration is complete or continuing
```

**On `bpf_pseudo_func`:**
```c
// a BPF_PSEUDO_FUNC instr is used for function pointers in BPF programs
// it loads a fucntion address into a register
```

**On non-branch/plain instructions:**
```c
// ABS and IND are abnormal instructions
// this adds both the fall through and the abnormal exit as successors
// ld_imm64 takes 2 instr slots
```

**On `BPF_EXIT`:**
```c
// exit has no successors
// leaf node in the CFG
```

**On `BPF_CALL`, overall:**
```c
// all helper calls, kernal function calls (kfuncs)
// BPF to BPF calls, callback calls (sync and async)
```

**Async callback:**
```c
// an async callback is a callback that is not called immmediately
// it is scheduled to run later
// like timer callbacks, task work callback etc
// when we encounter an async callback registeration, we need to
// verify the callback functions code
// then return to the instruction after call
// the prune point allows the verifier to stop exploring this path
// once the callback is verified, because the callback is nto
// executed immediately
```

**Sync callback:**
```c
// a syncronous callback is called immediately during execution of the helper
mark_calls_callback(env, t); // this isntruction calls a callback
mark_force_checkpoint(env, t); // must save state here
mark_prune_point(env, t); // can prune here
mark_jmp_point(env, t); // jump target for returns
```

**Plain helper calls:**
```c
// calls to the kernel helper fucntions
// eg : bpf_map_lookup_elem(), bpf_get_prandom_u32(), etc.
// get_helper_proto() looks up the function prototype for the helper id
```
```c
// so by this, we are marking the sleepable subprogram, as further
// when verifier checks if any non-sleepable program calls a sleepable helper
// it gets rejected
// When packet data changes, any cached packet pointers become invalid
// The verifier uses changes_pkt_data to know when to invalidate packet pointers
// bpf_tail_call() is a special helper that jumps to another BPF program
```

**Kfunc calls:**
```c
// kfuncs are kernel functions which can be called directly by the eBPF programs
// unlike the helpers which are called through the BPF helper API
// this gathers info about the kfunc
```
```c
// these are iterator next kfuncs
// basiccally these are called in loops
// for eg.
/*  struct bpf_iter_num it;
    bpf_iter_num_new(&it, 0, 10);
    while (bpf_iter_num_next(&it)) {  // ← This is the iterator next call
                                // Do something with each value
    }
    bpf_iter_num_destroy(&it);
*/
// so the verifier basically has to detect covnergence (know when the loop has stabilisd)
//  mark prune points (stop exploring when no new states are discovered)
// Force checkpoints (save state at each iteration to detect convergence)
```
```c
// sleepable kfuncs like bpf_copy_from_user(), bpf_copy_to_user(), etc.
// When packet data changes, any cached packet pointers become invalid
// The verifier uses this to know when to invalidate packet pointers
```

**On `BPF_JA`:**
```c
// unconditional jump instr.
// there are two types
// direct jump : BPF_K : target is a constant offset encoded in the instr.
// indirect jump : BPF_X : target is computed at runtime from a register value

// indirect jumps where we need to push each of the target instr on the stack and
// verifier would need to check each of these
// two types of unconditional direct jumps further
// one is 64 bit jumps : BPF_JMP (original one) : offset stored in insn->off
// other is 32 bit jumps : BPF_JMP32 (added later for smaller encoding) : offset stored in insn->imm (immediate)

// target = t + off + 1
// since there is only one succesor the verifier treats it as FALLTHROUGH
// other type of edge is BRANCH : in this there are usually two paths
// this is important wrt back edge detection
mark_jmp_point(env, t + off + 1); // Marks the target as a jump point for history tracking
// this is used for precision backtracking
```

**On the default (conditional-jump) case:**
```c
// default cases for conditional jumps
// contains all the conditional branch isntructions exceptht the ones that we already saw
// BPF_EXIT, BPF_JA, BPF_CALL
// these have two succesors FALLTHROUGH and BRANCH depending on the truth value of the condition
// may goto is a special type of instruction for bounded loops
```

**Expansion:** this is the per-instruction visitor called once per DFS step in `check_cfg()`. Its job is purely to classify the current instruction and report its successor edges — it does not simulate the instruction's effect (that's `do_check_insn()`'s job, later). The `mark_prune_point()`/`mark_force_checkpoint()`/`mark_calls_callback()`/`mark_jmp_point()` calls scattered through the branches are all bookkeeping for later phases: prune points let the main verification loop skip re-exploring a path once an equivalent state has been seen; force-checkpoints guarantee a state gets saved at points (like iterator-next calls) where skipping it risks pathological non-convergence.

---

## 11. `check_cfg()`

```c
static int check_cfg(struct bpf_verifier_env *env)
{
    int insn_cnt = env->prog->len; // total number of instructions
    int *insn_stack, *insn_state; // stack used for DFS, insn_state used to track the state of each instr during DFS
    // insns_state : 0 = not visited, DISCOVERED , EXPLORED
    int ex_insn_beg, i, ret = 0;
    // ex_insn_beg is starting instruction of the exeption callback
    // i, ret = loop counters and return value
    // insn_state[i] tracks the state of the instruction i
    // insn_stack is the DFS stack (which instruction to process next)
```

Further in:
```c
// if there is an exception callback subprogram (for bpfthrow)
// get its start instruciton
// otherwise it is equal to 0
// exception callbacks are optional subprograms that handle exception
// they need to be verified even if theyre not reachable from the main program
//. we will start a seperate dfs walk from this instruciton
```

```c
// MAIN DFS LOOP
walk_cfg:  // label for jumping back
        int t = insn_stack[env->cfg.cur_stack - 1]; // top of stack
        ret = visit_insn(t, env); // process this instr and its successors
        case DONE_EXPLORING: // if theinstr fully processed, pop it
        case KEEP_EXPLORING: // there are more instrns to explore, keep it
```

```c
// if there is an exception callback and it wasnt reached form the mai program
 // mark it as discovered, push it onto the stack
 // jump back to walk_cfg to explore it
```
```c
// every instrcution must be explored (reachable)
```
```c
// BPF_LD_IMM64 is a 64 bit immediate load instr, it lloads a 64-bit value
// into a register, immediate field is only 32 bits, so we need two conseucitve
// instr, second one would be a pseudo inst, like lui (upper immediate)
// cfg must treat these as one logical unit
// if a jump lands on second instr, it would corrupt the load
```

**Expansion:** this is the non-recursive DFS that detects loops (a loop is any back-edge in the instruction graph) and rejects unreachable code. It's explicitly non-recursive — using `insn_stack[]` as an explicit array rather than actual call-stack recursion — precisely so a deeply nested BPF program can't overflow the kernel's own call stack. The exception-callback handling is a special case: `bpf_throw()` callbacks are optional and might genuinely be unreachable from the main program's normal flow, so the DFS has to separately seed a walk from that entry point to make sure it still gets verified. The `ld_imm64` check at the end reflects that a 64-bit immediate load occupies two instruction slots — the CFG has to treat that pair as one unit, or a jump landing on the second half would silently corrupt the load.

---

## 12. `compute_postorder()`

```c
// REVERSE DFS ORDER
// used for liveness analysis (backward dataflow analysis) and state pruning
```

```c
// cur_postorder = current index in the postorder array
// i = loop counter over subprograms
// top = current insn being processed
// stack_sz = size of the DFS stack (how many succesors are pending)
// s = loop counter over succesors
// stack = DFS stack
// postorder = output array
// state = tracks DFS state for each insn
// succ = successors of the current insn
u32 cur_postorder, i, top, stack_sz, s;
```

```c
// for each subprogram
// each subprogram has its own contiguous range in the postorder array
// as postorder is only meaningful within a single function
```

**Expansion:** builds a reverse-DFS-order array of instructions, computed separately per subprogram (postorder ordering is only meaningful within a single function's own instruction range, not across the whole program). This ordering feeds backward liveness analysis later in `bpf_check()`.

---

## 13. `do_check_insn()`

```c
// It's the instruction dispatcher. It looks at the current instruction, determines its type (ALU, load, store, jump, call, etc.),
// and calls the appropriate handler function. It also handles some special cases like atomic operations, speculative execution, and exit paths.
// it is called by do_check()
static int do_check_insn(struct bpf_verifier_env *env, bool *do_print_state)
```

**On `BPF_ALU`/load:**
```c
// arithmetic insn
// load insn
// load from memory into register
// reads address form src_reg + off and stores in dst_reg
```

**On `BPF_STX` / atomics:**
```c
// store inc. atomic
// store from register into memory
// read from src_reg and write to address in dst_reg + off
```
```c
// atomic instructions
// single instructions that do mulitple things (read-modify-write)
// they dont have a seperate nextr instn to process
// thats why once we are done with it, we incrememnt the instn counter
// and return
// this prevents the verifire to process this insn again
```
```c
// check that the src_reg is valid and can be used as a source operand
```

**On `BPF_ST`:**
```c
// store an immediate value into memory
// reads immediate value from insn->imm and writes to address in dst_reg + off
```
```c
// check that the dst_reg is valid and can be used as a destination operand
// check_mem_access checks that the memory access is valid and that the destination register is writable
// check that the destination register is a pointer to memory or BTF ID
```

**On `BPF_JMP`/`BPF_JMP32`:**
```c
// control flow
// differnce between bpf_jmp and bpf_jmp32 is that the latter only uses 32 bits of the register for comparison
// 32-bit jumps were added later to support smaller encodings and to allow jumps with larger offsets (since imm is 32-bit vs off is 16-bit).
// bpf_jmp32 uses imm for the jump offset, while bpf_jmp uses off. This allows for larger jump offsets in bpf_jmp32, which is useful for larger programs.
// imm is a 32-bit signed immediate value that is used for comparison in conditional jumps, while off is a 16-bit signed offset that is used for unconditional jumps.
```

**On `BPF_CALL`:**
```c
// check that the call instruction is valid and that the source register is a valid function pointer or helper function
```
```c
// check that the call is not made while holding a lock, as this can lead to deadlocks or other synchronization issues
```

**On `BPF_JA`:**
```c
// unconditional jump
// indirect jump, check that the instruction is valid and that the source register is a valid function pointer or helper function
```
```c
// check that the jump instruction is valid and that the source and destination registers are valid
```

**On `BPF_EXIT`:**
```c
// exit instruction, check that the exit instruction is valid and that the source and destination registers are valid
```

**On default (conditional jump):**
```c
// conditional jump, check that the conditional jump instruction is valid and that the source and destination registers are valid
```

**On `BPF_LD`:**
```c
// load immediate/ abs immediate
// BPF_ABS : load from packet data at absolute offset insn->imm
// BPF_IND : load from packet data at offset (absolute or indirect)
// these are mainly used for readhing packet data in networking programs,
// where the offset is specified in the instruction and the data is read from the packet buffer.
// BPF_IMM : load immediate value into register
```

**Expansion:** this is the symbolic-execution counterpart to `visit_insn()` — where `visit_insn()` (used earlier, during CFG construction) only classifies an instruction and reports its successors, `do_check_insn()` is what actually *simulates* the instruction's effect on the verifier's tracked register/stack state during the main verification pass. The lock-check before `BPF_CALL` (rejecting calls made while holding a spinlock) is a deadlock-prevention rule; the `BPF_JMP` vs `BPF_JMP32` distinction reflects a real historical addition to the instruction set for more compact jump encoding.

---

## 14. `do_check()`

```c
// iterates through instuctions one by one
// checks if you can prune the current path
// simulates the instruciton
// handles branches
// handles exits
static int do_check(struct bpf_verifier_env *env)
```
```c
// pop_log = Whether to pop log entries (true if not ultra-verbose)
// state = Current verifier state (registers, stack, etc.)
// insns = The program's bytecode instructions
// insn_cnt = Total number of instructions
// do_print_state = Whether to print the state in the next log
// prev_insn_idx = Previous instruction index (for jump history)
```

Inside the main loop:
```c
// ensure insn index is valid
```
```c
// complexity limit check
```
```c
// if it has been marked as a prune point (conditional jumps, jump targets, etc.)
// check if an equivalent state has already been visited
```
```c
// if the insn is a jump target
```
```c
// offload verification
```
```c
// mark insn as seen
```

**Expansion:** this is the main verification loop — the outer driver that repeatedly calls `do_check_insn()` per instruction. The prune-point / `is_state_visited()` check is the core mechanism that keeps loop/branch exploration finite: if the current instruction was marked as a prune point (by `visit_insn()`, during CFG construction) and an equivalent state has already been explored from here, the current path is safe to stop exploring. The complexity-limit check is the concrete ceiling (`BPF_COMPLEXITY_LIMIT_INSNS`) the verifier enforces to guarantee it always terminates.

---

## 15. `bpf_check()`

```c
/* bpf_check() is the main entry point..it takes arguments:
1) prog ( main input/output ) double pointer to the bpf program being verified: The verifier may need to replace the program during verification (in the end it rewrites the code and optimizes)
                                                   : the caller passes a pointer to its struct bpf_prog* variable
                                                   : if verification succeeds, prog might point to a new/modified program
2) union bpf_attr *attr which is a pointer to large union that contains all the parameters for the BPF syscall. it contains features like
                                                    : prog type which determines which verifier operations to use (???)
                                                    : insns which is the actual bytecode
                                                    : log_level/ log_buf/ log_size which indicates the logging controls
                                                    : and others..
and other arguments which we will discover as it goes ahead
 */
```

**Setup phase:**
```c
// INITIAL SETUP AND VARIABLE DECLARATIONS
u64 start_time = ktime_get_ns(); // records when verification started purely for performace stats
struct bpf_verifier_env *env;  // the main verifier state structure (will be allocated later)
int i, len, ret = -EINVAL, err; // return code, initialised to -EINVAL (invalid argument)
u32 log_true_size;  // will store the actual log size needed

bool is_priv; // whether the caller has CAP_BPF (privileged)
// CAP_BPF is a capabilityt which allows a process to load eBPF programs and create maps
// but on its own, CAP_BPF is not enough for all type of programs, we would also need things like
// CAP_NET_ADMIN and CAP_PERFMON for other netowrking / tracing programs
// we need this as the verifier enforces additional safety restructions when
// CAP_BPF is absent, and does more agressive code optimizations for priveleged users
// like removing dead code, hard wire branches and remove NOP instrcutions (instruction that tells the CPU to do nothing)
// it basically specifies exactly which bpf() syscall commans, program types, map types and attach types are allowed

// macro that forces the compiler to include type information for a specific C type
// in the vmlinux BTF(BPF type format) section of the kernel (?????)
/* no program is valid */ // ???????
```

**Environment allocation:**
```c
// bpf_verifier_env is the mother fo all the verifier state containers, it holds everything
// the program, program type specific operations, stadkc of states to explore(DFS)
// stack_size, current state beign processed, per instruction metadata
// hash table for state prining, states available for reuse, register and stack state
// logging, etc and others like BTF information, used maps and BTFs, backtracking state, etc
// the env is the central data strcuture that the verifier catries around everywhere
// it will be passed to almost every funciton
// kvzalloc is a memory allocation fucntion in the linux kernel, it is a combination of kvmalloc
// and kzalloc, it attempts to allocate physically contiguous memory (like kmallox)
// but automatically falls back to non contiguous virtual memory (like vmalloc) if the allocation fails
```
```c
env->bt.env = env;
// bt is of type struct backtrack_state
// struct backttrack_state contains pointer struct bpf_verifier_env again
// its used during precision backtracking (state pruning) (?????)
// so this line sets up a circulr reference so that env points back to paretn env
// so bt struct has access to everything in env through its env pointer
// so now we have allocated the environment now we move forward to setup and initialization
```

**Instruction auxiliary data / successor array / ops setup:**
```c
// Instruction auxillary data allocation
len = (*prog)->len; // num of instructions in the BPF program
// we are allocating an array of struct bpf_insn_aux_data
// one entry per instruction

// each instruction needs auxillary metadata, as the verifier may patch/replace
// instruction, so we need to track the original indices
// orig_idx helps map patched instrctions back to their source

// SUCCESSOR ARRAY ALLOCATION
env->succ = iarray_realloc(NULL, 2);  // allocate space for 2 successors per instr.
// we need this inst successor array for CFG(control flow graph) building
// most instr hav 2 successors

// SET PROGRAM AND OPS
// each program type has its own verifier ops
// eg : xdp_verifier_ops, tracing_verifier_ops, etc
// CAPABILITY FLAGS (???)
```

**BTF / logging / FD phase:**
```c
// this ensures the kernel 's BTF (BPF type format) is loaded
// its a global variable btf_vmlinux

// LOGGING AND FD PROCESSING PHASE
// if the user is not priviliged(CAP_BPF), acquire a global lock to protect shared resources
```
```c
// this sets up the verifiers logging system
// if the user provided a log buffer, all verbose() messages will go there

// processes file descriptors passed from userspace (maps and BTFs referenced by the program)
mark_verifier_state_clean(env); // resets the tracking for verbose logging
// BTF AND SUBPROGRAM DISCOVERY PHASE
// this is where the verifier discoers what functions exist in the program and what types it uses
// checks if the kernel's BTF (type info) is available
// without this, programs thatuse kernel types cant be verified

// decided if memory accesses must be naturally aliogned (strict)
// or if unaligned is allowed
// some cpus cant handle unaligned access efficiently
// two types of alignment - STRICT OR ANY

// this enables test flags only for privileged ysers
// these are for debugging/testing the verifier itself
// allocates the hash table for state pruning (?????)
// each entry is a list of previously explored states at that instruction index
```

**Analysis phase — one line per pipeline stage:**
```c
// ACTUAL ANALYSIS OF PROGRAM STARTS
// early lightweight BTF validation
// checks that the BTF info is present and valid, doesnt do type checking yet
// discovers all subprograms(fucntions) and kfuncs(kernel function calls)
// builds the env->subprog_info array
// validates that jumps stay within their own subprogram and that each subprogram ends
// with a valid exit instr.
// full BTF validation
// matches BTF function info with discovered subprograms, validates line info (debugging info),
// processes CO-RE relocations
// converts pseudo instructions into real ones
// maps fd reference to actual map pointers
// btf ids to kernel symbol addresses
// function pointers to actual function addresses
// for programs that are offloafed to hardware(NIC,etc), prepares the offload driver for verification(?????)
//THE CFG AND THE LIVENESS PHASE
// builds the control flow graph, detects loops(back edges) and rejects them
// finds unreachable code
// this is the first safety check
// computes a post order traversal of the CFG
// used for backward liveness analysis
// backward liveness analysis is done so that at each step, we know which registers
// are going to be used ahead and which arent gonna be
// this helps us during symbolic execution for changing state and knowing
// which registers can be overwritten with

// initialises stack liveness tracking (whihc stack slots are live)
// validates that the program is attached to the correct kernel function
//computes scc in the cfg
// identifies loop structures for better state pruning
    // computes which registers are live at each instructin
    // used for precision tracking and state pruning
    // basically backward liveness analysis
//identifies bpf_fastcall patterns (compiler optimized calls)
// so that they can be optimized later  (?????)
```

**Main verification call:**
```c
// THE MAIN EVENT : VERIFICIATION
//this is where the verifier actually simulates the program
ret = do_check_main(env); // verifies the main program(entry point)
ret = ret ?: do_check_subprogs(env); // verifies all global subprograms
// this runs the state simulation with all the pruning and safety checks we discussed earlier
```

**Wind-down:**
```c
// if verificaiton succeeded and program is offloaded finalise the offload
// BPF with offload(hardware): we write a BPF program, the verifier still does its safety checks
// but instrad of just createing code for CPU, the process extends into the NIC driver
// the driver works with the hardware, to translate the BPF bytecode into a format the
// NIC's accelerator can execute, the program is then programmed into the NIC hardware
// (?????)

//bpf_prog_is_offloaded checks if the program is intended forhardware offload

//POST VERIFICATION OPTIMIZATIONS
```

**Expansion:** this is the syscall-level entry point for the whole verifier, called once per `BPF_PROG_LOAD`. My comments walk through it phase by phase: environment allocation (the `struct bpf_verifier_env` that gets threaded through nearly every function in the file), instruction auxiliary-data setup, then the analysis pipeline in the order it actually executes — early BTF checks, subprogram/kfunc discovery, full BTF validation, pseudo-instruction resolution, CFG construction (`check_cfg()`), postorder computation, liveness analysis, SCC computation, and finally the main symbolic-execution pass (`do_check_main` / `do_check_subprogs`) — followed by post-verification optimization and hardware-offload finalization.

**Open items I flagged with `(?????)` while annotating — not yet resolved:**
- The exact purpose/mechanics of the BTF-type-emission macro used in setup.
- What "prog type... which verifier operations to use" fully entails (referenced in the function's own doc-comment).
- The precise role of `env->bt.env`'s circular reference during precision backtracking.
- Details of the hardware-offload driver handoff.
- What exactly "identifies bpf_fastcall patterns... so that they can be optimized later" optimizes, mechanically.
- The state-pruning hash table's allocation details.

These are honest gaps in my current understanding, left marked rather than guessed at, and are good candidates to raise directly if useful.

---

## Summary table

| # | Function | What's annotated |
|---|---|---|
| 1 | `check_map_access_type` | Purpose (one-liner) |
| 2 | `__check_mem_access` | Parameter meanings (`regno`, `off`) |
| 3 | `check_map_access` | Two-stage structure; kptr/spin-lock/timer field overlap logic |
| 4 | `check_mem_access` | Function-level structure; `MAP_KEY`, `MAP_VALUE`, `PTR_TO_MEM` branches; probe-read mechanism |
| 5 | `check_helper_call` | Function-level summary only (body not yet annotated) |
| 6 | `check_alu_op` | One opcode (`BPF_END`) |
| 7 | `check_cond_jmp_op` | Full branch-forking / range-refinement / pointer-comparison logic |
| 8 | `visit_gotox_insn` | Jump-table lookup/creation |
| 9 | `visit_abnormal_return_insn` | Hidden-exit successor registration |
| 10 | `visit_insn` | Full per-instruction-type dispatch, incl. kfunc/callback/iterator handling |
| 11 | `check_cfg` | DFS loop-detection setup, main loop, exception-callback pass, `ld_imm64` pairing |
| 12 | `compute_postorder` | Purpose, variable roles, per-subprogram ranging |
| 13 | `do_check_insn` | Full instruction-class dispatch |
| 14 | `do_check` | Main loop structure, prune-point/complexity-limit mechanics |
| 15 | `bpf_check` | Full phase-by-phase walkthrough, with explicit open questions flagged |

**Functions that came up while reading but were *not* touched** (no comments added, so intentionally excluded above even though they sit right next to annotated functions): `check_stack_write`, `get_func_retval_range`, `in_sleepable_context`, `sync_linked_regs`, `check_indirect_jump`, `states_equal`, `compute_scc`.

**Planned next, in order:** `PTR_TO_STACK` branch of `check_mem_access` → `check_helper_call` body → `check_kfunc_call` → `is_branch_taken()` → a synthesis pass mapping each subsystem above to what KEEL's proof-carrying architecture replaces.
