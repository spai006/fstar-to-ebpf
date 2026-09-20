# F* to eBPF

Research project under [FP Launchpad](https://fplaunchpad.com), IIT Madras.

## What this is

The Linux eBPF verifier is a ~26,000 line C file that performs abstract interpretation on every eBPF program before it is loaded into the kernel. It is informally specified, rapidly evolving, and has a history of soundness bugs.

This project explores a **Proof-Carrying Code (PCC)** approach to eBPF safety. Instead of the kernel discovering safety at load time, programs would arrive with a machine-checkable proof certificate. The kernel would only need a small, auditable checker — shrinking the Trusted Computing Base significantly.

```
Developer
  ↓
Write program in F* (or equivalent proof-oriented language)
  ↓
Userspace certifier — generate proof certificate
  ↓
Compile to eBPF bytecode
  ↓
Kernel proof checker (small, auditable)
  ↓
PASS / FAIL
```

The typed intermediate representation at the center of this is **KEEL** — designed so that a well-typed KEEL term directly encodes all safety-relevant facts, and the backend compiler produces both eBPF bytecode and a compact certificate from it.

## Current status

Studying the Linux BPF verifier (`kernel/bpf/verifier.c`) in depth — understanding what each subsystem does, so we can reason about which responsibilities disappear in a proof-carrying architecture.

**Papers read:** PREVAIL, VEP, BCF ("Prove It to the Kernel"), Pretty Verifier, ExoVerifier, Agni

**Verifier subsystems studied:**
- CFG construction and loop detection (`check_cfg`)
- Liveness analysis (`compute_live_registers`)
- Main simulation loop (`do_check`, `do_check_insn`)
- Memory access validation (`check_mem_access`)
- ALU operations (`check_alu_op`)
- Conditional branch reasoning (`check_cond_jmp_op`)
- Helper call validation (`check_helper_call`)
- State pruning (`is_state_visited`)
- Precision tracking (`mark_chain_precision`)

## Repo structure

```
notes/
  verifier-internals.md       ← conceptual notes on each verifier subsystem
  papers.md                   ← notes on related work
  research-questions.md       ← open questions and design gaps

code/
  verifier.c                  ← annotated kernel source (comments added on top of clean snapshot)

logs/
  verifier_c_annotation_log.md  ← precise record of what has been annotated and why

experiments/
  README.md                   ← setup notes for running kernel under QEMU + GDB coverage analysis
```

## Research question

> If eBPF programs arrived with machine-checkable proof certificates, which parts of the Linux verifier would still be necessary — and which are artifacts of discovering safety at load time?

## Related work

| System | What it does |
|---|---|
| PREVAIL | Abstract interpretation based verifier built on Crab, used by eBPF for Windows |
| VEP | Two-stage verification — annotated C source + custom IR |
| BCF | PCC with abstraction refinement as fallback to verifier rejection |
| ExoVerifier / ExoBPF | Moves proof generation to userspace, adds small in-kernel checker |
| Agni | Formally verifies the verifier's abstract domains (tnum, interval) using SMT |

## Advisor

Project under [Pragyansh Chaturvedi](mailto:pragyansh@fplaunchpad.com), FP Launchpad, IIT Madras
