# Linux BPF Verifier Internals

> Study notes for the FP Launchpad project (F* to eBPF / PCC for eBPF).
> Goal: understand what each verifier subsystem does, so we can later reason about
> which responsibilities disappear in a proof-carrying architecture.

---

## Mental Model

The verifier is a **symbolic interpreter**. It never runs the program.
Instead, it maintains a *belief* about the program state at every point —
what type each register holds, what range its value is in, whether it might be NULL —
and updates that belief instruction by instruction across every possible path.

Think of each register as having a **medical record** (`bpf_reg_state`):
not a value, but a description — type, range, offset, reference ownership.
Every instruction updates that record.

---

## Verification Pipeline

```
bpf_check()                        ← entry point (one call per BPF_PROG_LOAD)
│
├── Setup
│   ├── Allocate bpf_verifier_env
│   ├── Allocate insn_aux_data[]    ← one entry per instruction
│   └── Set program type + verifier ops (xdp_verifier_ops, tracing_verifier_ops, …)
│
├── BTF & Subprogram Discovery
│   ├── check_btf_info_early()      ← lightweight: is BTF present and valid?
│   ├── add_subprog_and_kfunc()     ← discover functions + kfunc calls → env->subprog_info[]
│   ├── check_subprogs()            ← jumps stay within subprogram; each ends with EXIT
│   ├── check_btf_info()            ← full BTF validation, CO-RE relocations, line info
│   └── resolve_pseudo_ldimm64()    ← map FDs → kernel pointers, BTF IDs → symbols
│
├── CFG + Liveness
│   ├── check_cfg()                 ← DFS: build CFG, detect back-edges, reject unreachable code
│   ├── compute_postorder()         ← reverse DFS order, needed for backward analysis
│   ├── compute_scc()               ← Tarjan SCC: identify loop structures
│   └── compute_live_registers()    ← backward liveness (USE/DEF equations, fixpoint over cycles)
│
├── Main Verification   ← THE HEART
│   ├── do_check_main()             ← verify entry point
│   └── do_check_subprogs()         ← verify all global subprograms
│
└── Post-Verification
    ├── convert_ctx_accesses()      ← abstract ctx accesses → real kernel struct offsets
    ├── do_misc_fixups()            ← inline helpers, rewrite division, patch tail calls, Spectre barriers
    ├── sanitize_dead_code()        ← unreachable insns → `ja -1` (infinite trap)
    └── jit_subprogs()              ← JIT compile each subprogram, patch call addresses
```

---

## Core Data Structures

### `bpf_verifier_env`
Global context threaded through every function. Contains:
- The program being verified
- Current verifier state
- `insn_aux_data[]` — per-instruction metadata (prune points, ALU limits, map pointers)
- Explored-states hash table (for pruning)
- Logging state
- Used maps and BTFs

### `bpf_verifier_state`
The complete symbolic state at one point in execution. Contains:
- One `bpf_func_state` per call frame
- Current instruction index
- Branch depth

### `bpf_func_state`
State of one call frame. Contains:
- `regs[MAX_BPF_REG]` — register states
- `stack[]` — stack slot states (spilled registers, zeroed, uninitialized)
- Reference state (acquired/unreleased references)

### `bpf_reg_state`
The "medical record" of one register. Key fields:

| Field | Meaning |
|---|---|
| `type` | `SCALAR_VALUE`, `PTR_TO_CTX`, `PTR_TO_MAP_VALUE`, `PTR_TO_STACK`, … |
| `smin_value` / `smax_value` | Signed range |
| `umin_value` / `umax_value` | Unsigned range |
| `var_off` | Tnum — tracks known/unknown bits exactly |
| `id` | Pointer identity (linked registers share an ID) |
| `off` | Fixed offset from pointer base |
| `map_ptr` | Which map this points into (for `PTR_TO_MAP_VALUE`) |

**Why both ranges and tnum?**
Ranges (`umin`/`umax`) are cheap for arithmetic but lose bit-level structure.
Tnum (`var_off`) tracks exactly which bits are known — needed for precise bounds after bitwise ops.
After every operation, `reg_bounds_sync()` keeps them consistent.

---

## Subsystem 1: CFG Construction (`check_cfg`)

**Why it exists:** The verifier must know the shape of the program before simulating it.
Loops, unreachable code, and malformed jumps all need to be caught first.

**What it does:**
- DFS over instructions using `visit_insn()` to find each instruction's successors
- Detects **back-edges** (a cycle in the DFS tree) → bounded loops only
- Rejects unreachable instructions (they bypass safety checks)
- Validates that jumps land within the program and within their subprogram

**Key helpers:**
- `visit_insn()` — determines successors for normal instructions and jumps
- `visit_gotox_insn()` — handles indirect jumps (jump tables)
- `visit_abnormal_return_insn()` — registers hidden exits for `LD_ABS`/`LD_IND`/tail calls

**PCC relevance:** In a proof-carrying architecture, the certificate would be indexed by instruction.
CFG construction might still be needed to validate that the certificate's structure matches the program.
But loop rejection would move to the proof obligation (termination proof in the certificate).

---

## Subsystem 2: Liveness Analysis (`compute_live_registers`)

**Why it exists:** State pruning (see below) needs to know which register values actually matter
at a given point. If a register is dead (will be overwritten before being read), its current value
cannot affect future execution — so two states that differ only in dead registers are equivalent.

**How it works:**
- Backward dataflow: start from exits, propagate USE/DEF sets backward
- A register is **live** at instruction N if it will be read before being overwritten
- Tracks both registers and stack slots
- Must iterate to a **fixpoint** over cycles (a loop counter is live across a back-edge —
  this is normal, not a rejection condition)

**What it feeds:** `is_state_visited()` uses liveness to ignore dead registers when comparing states.

**PCC relevance:** Liveness analysis itself might not be needed — the certificate would carry
explicit annotations about which values matter. But some form of it might survive inside the checker
to validate those annotations.

---

## Subsystem 3: Main Simulation Loop (`do_check`)

**How it works:**
1. For each instruction on the current path:
   - Call `is_state_visited()` — can we prune here?
   - If not, call `do_check_insn()` — simulate the instruction, update register state
   - If the instruction is a branch with both sides reachable: `push_stack()` the other branch, explore this one first
2. When a path ends (EXIT or pruned): `pop_stack()` and continue with the saved branch
3. Repeat until all paths are explored or a limit is hit (`BPF_COMPLEXITY_LIMIT_INSNS = 1,000,000`)

**`do_check_insn()` dispatches to:**

| Instruction class | Handler |
|---|---|
| ALU ops | `check_alu_op()` |
| Memory load | `check_load_mem()` |
| Memory store | `check_store_reg()` |
| Atomic ops | `check_atomic()` |
| Conditional jump | `check_cond_jmp_op()` |
| Helper call | `check_helper_call()` |
| kfunc call | `check_kfunc_call()` |
| Immediate load | `check_ld_imm()` |
| Packet load | `check_ld_abs()` |

---

## Subsystem 4: Memory Access Validation (`check_mem_access`)

**Why it exists:** eBPF programs run in kernel space. Any out-of-bounds or type-confused
memory access is a kernel safety violation.

**Three-step structure:**
1. Convert `bpf_size` enum → bytes
2. Check alignment (strict or permissive depending on CPU/program type)
3. Branch on pointer type → different rules per type

**Pointer types and their rules:**

| Pointer type | What's checked |
|---|---|
| `PTR_TO_MAP_KEY` | Read-only; within `map->key_size`; result is scalar |
| `PTR_TO_MAP_VALUE` | No writing pointers into maps (info leak); read/write capability flags; bounds + kptr overlap check |
| `PTR_TO_STACK` | Within `[-512, 0)`; alignment; spill/fill tracking |
| `PTR_TO_CTX` | Program-type-specific rules via `check_ctx_access()` |
| `PTR_TO_MEM` | Known-size memory chunk; nullable check must pass first; rdonly enforcement |
| `PTR_TO_BTF_ID` | Kernel struct access; type-checked via BTF |
| `PTR_TO_PACKET` | Packet data; range must be within `data`..`data_end` |

**Special case — kptr fields in map values:**
Map values can contain kernel pointers (`BPF_KPTR_REF`, `BPF_KPTR_UNREF`).
Rules for accessing them:
- Only direct load/store — no helper access (`ACCESS_HELPER` is rejected)
- Offset must be a compile-time constant
- Access must start exactly at the field and be exactly 8 bytes

**`check_map_access()` structure:**
1. `check_mem_region_access()` — ordinary `smin`/`umax` bounds arithmetic
2. If the map has a `btf_record` (special fields), check every field for interval overlap with the access

---

## Subsystem 5: ALU Operations (`check_alu_op`)

**What it does:** For every arithmetic/logic instruction, updates the destination register's
symbolic state (type, ranges, tnum).

**Scalar arithmetic (`adjust_scalar_min_max_vals`):**
- Computes new `smin`/`smax`/`umin`/`umax`/`u32_min`/`u32_max` for ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, shifts
- Calls `reg_bounds_sync()` after every update to keep ranges and tnum consistent

**Pointer arithmetic (`adjust_ptr_min_max_vals`):**
- Only scalar + pointer is allowed (not pointer + pointer)
- Updates `reg->off` (fixed offset) and range information
- Adds Spectre sanitization metadata where needed

**Special case — `BPF_END` (byte-swap):**
After a byteswap, the verifier cannot maintain meaningful range information —
the bit pattern is rearranged in a way that invalidates signed/unsigned bounds.
So the destination register's ranges are reset to the full unknown range.

---

## Subsystem 6: Conditional Branches (`check_cond_jmp_op`)

**What it does:**
1. Calls `is_branch_taken()` — if the condition is statically known (e.g., comparing two constants),
   only explore that branch
2. Otherwise: explore both branches
3. On each branch: calls `reg_set_min_max()` to **refine register ranges** given the branch condition
   - e.g., after `if r1 < 10: goto taken`, on the taken branch: `r1.umax = 9`
4. Resolves nullable pointers: `PTR_MAYBE_NULL` becomes `PTR_TO_MAP_VALUE` on the non-null branch
   and `SCALAR_VALUE` (= 0) on the null branch

**Linked registers:** If `r1` and `r2` share an ID (meaning they were equal at some point),
a range refinement on `r1` propagates to `r2` via `sync_linked_regs()`.

---

## Subsystem 7: Helper Calls (`check_helper_call`)

**What it does:**
1. `get_helper_proto()` — fetch the helper's argument/return type specification
2. `check_func_arg()` — validate each argument:
   - Register type matches expected type (`ARG_PTR_TO_MAP_KEY`, `ARG_CONST_SIZE`, etc.)
   - Memory regions are initialized and within bounds
   - Reference ownership is correct
3. Track reference acquisition/release
4. Set `r0`'s type based on the helper's return type (`RET_PTR_TO_MAP_VALUE_OR_NULL`, etc.)
5. Handle special helpers (`tail_call`, `bpf_loop`, timer callbacks)

**Reference tracking:**
Some helpers acquire kernel object references (e.g., `bpf_sk_lookup_tcp` → socket reference).
The verifier tracks these via `acquire_reference()` / `release_reference()`.
At program exit, `check_reference_leak()` ensures every acquired reference was released.

If a reference is acquired on one branch of a conditional but not the other,
both branches must eventually release it before exit — the verifier enforces this
by tracking reference state per path.

---

## Subsystem 8: State Pruning (`is_state_visited`)

**Why it exists:** Path-sensitive analysis of a branchy program is exponential without pruning.
If we reach instruction N with a state that is "at least as safe" as a previously verified state
at instruction N, we don't need to re-explore — the already-verified path covers us.

**How it works (conceptually):**
- Explored states are stored in a **hash table** keyed by instruction index
- At each prune point, the current state is compared against all previously stored states at that instruction
- If the current state is **subsumed** by a stored state (every register's range is contained within
  the stored state's range, all pointer types match, live registers agree), pruning fires
- Liveness is critical here: dead registers are **ignored** during comparison —
  two states that differ only in dead register values are treated as equivalent

**What "subsumed" means concretely:**
- Scalar registers: current range ⊆ stored range (`regsafe()`)
- Stack slots: current slot type ⊆ stored slot type (`stacksafe()`)
- References: current references ⊆ stored references
- Only **live** registers/slots participate — dead ones are skipped

---

## Subsystem 9: Precision Tracking (`mark_chain_precision`)

**Why it exists:** State pruning compares ranges. But ranges can be imprecise —
a register might have range `[0, 100]` in both states even though one knows the exact value.
For some operations (bounds checks, pointer arithmetic), exact values matter.
Precision tracking marks which registers need **exact values** (not just ranges)
and propagates those marks **backward** through the instruction chain.

**How it works:**
- When a register's exact value is needed (e.g., used as a pointer offset),
  it is marked "precise"
- `mark_chain_precision()` walks backward from that instruction,
  marking all registers whose values contributed to this one as precise
- Precise registers are compared exactly (not just by range subsumption) during pruning

---

## Register File Summary

| Register | Role | Initial type |
|---|---|---|
| R0 | Return value | Set by helper return type |
| R1–R5 | Argument passing (caller-saved) | Undefined after call |
| R6–R9 | Callee-saved | Preserved across calls |
| R10 | Frame pointer (read-only) | `PTR_TO_STACK` |

At program entry: `R1 = PTR_TO_CTX` (pointer to the program's context struct).

---

## Open Questions (as of current study)

- Exact implementation of `states_equal()` / `regsafe()` / `stacksafe()`
- How the explored-states hash table is structured and keyed exactly
- `tnum` implementation details (tristate number arithmetic)
- Precision tracking mechanics in full detail
- `check_kfunc_call()` — kernel function call validation
- Post-verification fixups in detail (`convert_ctx_accesses`, `do_misc_fixups`)
- Hardware offload path (`bpf_prog_offload_*`)

---

## PCC Relevance Summary

| Verifier subsystem | Needed in certificate checker? |
|---|---|
| CFG construction | Partially — structure validation, not safety discovery |
| Liveness analysis | Probably not — certificate carries explicit annotations |
| State pruning | No — pruning is only needed when discovering proofs, not checking them |
| Precision tracking | No — same reason as pruning |
| Memory bounds checking | Yes — checker must still verify certificate claims against bytecode |
| Pointer type checking | Yes — type safety is a core safety property |
| Helper call validation | Partially — helper specs become part of the certificate format |
| Reference tracking | Yes — resource safety must still be enforced |
| Termination | Yes — but as a proof obligation in the certificate, not loop detection |
