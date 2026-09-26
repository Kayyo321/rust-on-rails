# rust-on-rails: Architecture & Specification Document

**Project Codename:** `rust-on-rails`  
**Base Upstream:** `rust-lang/rust`  
**Classification:** Confidential Systems Compiler & Adversarial Runtime  
**Core Syntax Marker:** `$` (Unified Confidentiality & Target Modifier)

**Specification Status:** Proposed language and runtime design; implementation and security validation are not yet established. Sections 8–19 refine the introductory examples and take precedence where an example implies a stronger guarantee. All new syntax, APIs, configuration keys, and diagnostics below are proposals, not existing Rust features.

---

## 1. Executive Summary & Philosophy

Current confidential computing frameworks rely on fragmented libraries, manual zeroization calls, and heavy foreign-function interface (FFI) plumbing. 

**rust-on-rails** elevates data privacy and isolation into first-class language mechanics. By utilizing the `$` sigil as an explicit syntactic qualifier for types, literals, data structures, functions, and target domains, rust-on-rails enables developers to write code that survives in hostile environments under a **Zero-Trust Host Model**—where the underlying operating system, supervisor layers, and memory buses are treated as untrusted or actively compromised.

---

## 2. Syntax & The `$` Unified Qualifier System

In standard Rust, `$` is reserved strictly for macro transcription. rust-on-rails reclaims `$` in normal code contexts, utilizing it as the universal compiler directive for privacy constraints, target isolation, and memory lifecycles.

### 2.1 Types, Literals, and Qualifiers

```rust
// Scalar held under runtime memory obfuscation/masking
const PIN: i32$crypt = 8492;

// Compile-time encrypted string literal loaded into dynamically scrambled memory
const MASTER_KEY: &str$crypt = "super_sensitive_token"$crypt;

// Explicit configuration parameters passed via parenthetical attributes
let seed: [u8; 32]$crypt(level = "paranoid", wipe = "instant") = [0u8; 32];
```

### 2.2 Tagged Structs and Functions (`fn$`, `struct$`)

Target domains and isolation properties are applied directly to identifiers using the `$` token:

```rust
// A confidential struct whose internal fields are automatically padded,
// split into XOR shares in RAM, and guaranteed to wipe on Drop
struct$crypt SessionRecord {
    user_id: u64,
    auth_token: [u8; 64]$crypt,
}

// Function compiled strictly for CPU hardware enclaves (Intel SGX, AMD SEV-SNP)
// Automatically scrubs all general-purpose and vector registers upon return
fn$enclave verify_remote_attestation(report: &[u8]$crypt) -> bool {
    // Execution is protected by CPU-level hardware memory encryption
    validate_report_signature(report)
}

// Function compiled to run as a bare-metal unikernel payload (Ring 0 / seL4 micro-VM)
// Eliminates the host OS entirely; no kernel layer to trust
fn$baremetal boot_isolated_keystore() -> ! {
    initialize_direct_page_tables();
    loop {}
}

// Function using pure user-space software defenses on standard OS targets
fn$defended sign_transaction(payload: &[u8]) -> [u8; 64]$crypt {
    // Software masking, anti-debug, and time-drift checks are active here
    generate_signature(payload)
}
```

---

## 3. Execution Targets & Threat Models

rust-on-rails provides three primary execution targets, selectable per item via the `$` qualifier or globally across compilation crates:

| Target Directives | Threat Model | Isolation Mechanism | Trade-Off |
| :--- | :--- | :--- | :--- |
| **`fn$enclave`** / **`struct$enclave`** | Protects against Ring 0 rootkits, malicious OS, physical memory scrapers. | Hardware-enforced encryption (Intel SGX, AMD SEV-SNP). | Boundary transition overhead; hardware vendor lock-in. |
| **`fn$baremetal`** / **`struct$baremetal`** | Eliminates host OS attack surface entirely. | Runs directly on bare metal or an seL4 microkernel without an OS. | No standard OS APIs; requires direct device/memory handling. |
| **`fn$defended`** / **`struct$crypt`** | Mitigates memory dumps, Cheat Engine, and cold-boot dumping on standard OS. | Software-level additive masking, register pinning, anti-tracing tripwires. | Measurable CPU and cache overhead; cannot permanently stop dedicated Ring 0 debuggers. |

---

## 4. User-Space Software Defense: Developer Guide & Practical Examples

When running in an environment without hardware enclaves or bare-metal access (such as a client desktop running Windows or Linux), the programmer can activate **User-Space Software Defense**. 

Because this incurs substantial CPU and memory overhead, rust-on-rails gives the developer full control over when and how these defenses are deployed.

### Example 1: In-Memory Additive Masking with PIN Entry

Below, an authentication handler accepts a PIN, processes it under dynamic 3-share memory masking, and automatically purges all execution artifacts:

```rust
// fn$defended instructs the compiler to emit adversarial defenses:
// 1. Inlines RDTSC timing fences before and after sensitive math
// 2. Prohibits spilling $crypt variables to the thread stack
fn$defended process_user_login(user_input: i32) -> bool {
    // $crypt forces the compiler to split stored_pin across 3 disparate memory pages:
    // Memory State: PageA = S1, PageB = S2, PageC = S3 where Pin = S1 ^ S2 ^ S3
    let stored_pin: i32$crypt(defense = "paranoid") = 7491;

    // Compile-time encrypted string that is only decrypted inside a vector register
    let failure_msg: &str$crypt = "Authentication Rejected"$crypt;

    // Comparison is compiled into constant-time, masked XOR arithmetic.
    // The raw value 7491 is never written to DRAM as an integer.
    let is_valid = constant_time_eq(user_input, stored_pin);

    if !is_valid {
        log_security_event(failure_msg);
    }

    // At this scope boundary:
    // 1. S1, S2, and S3 are overwritten via explicit zero-fill instructions
    // 2. All vector/general-purpose registers used in calculation are zeroed
    is_valid
}
```

### Example 2: Continuous Share Cycling & Decoy Allocations (Long-Lived Secrets)

For keys that must reside in RAM for prolonged periods, the developer can declare a rolling defense:

```rust
struct$crypt PrivateKeyStore {
    // Rotates memory addresses and re-masks shares every N milliseconds
    key_material: [u8; 32]$crypt(rotate_ms = 50, decoys = 4),
}

impl PrivateKeyStore {
    fn$defended decrypt_payload(&self, ciphertext: &[u8]) -> Vec<u8> {
        // The background thread pauses key rotation during this block
        // Reconstructs key directly in AVX registers, computes, and scrubs
        let cleartext = perform_aes_gcm(&self.key_material, ciphertext);
        cleartext
    }
}
```

### Example 3: Mitigating Overhead with Explicit Scoping

Because software defense incurs cache pollution and instruction bloat, developers should localize `$crypt` usage strictly to sensitive computation hot spots:

```rust
// Standard, high-performance networking function
fn handle_network_traffic(packet: &[u8]) {
    let header = parse_packet_header(packet); // Zero overhead, full optimization

    if header.is_authentication_frame() {
        // Drop into defended execution mode exclusively for secret processing
        process_secure_frame(packet);
    }
}

fn$defended process_secure_frame(packet: &[u8]) {
    let extracted_token: [u8; 64]$crypt = extract_token(packet);
    validate_with_auth_core(extracted_token);
    // extracted_token wiped instantly on next cycle
}
```

---

## 5. Security vs. Performance Trade-off Calibration

Developers configure performance limits in `Cargo.toml` or override them granularly using attribute syntax:

```toml
[profile.release.crypt]
default-defense = "balanced"        # "off", "balanced", or "paranoid"
enable-anti-tracing = true         # Emits RDTSC time-drift tripwires
max-stack-spill-registers = 8      # Limits register pinning to prevent pressure stalls
```

### Granular Defense Matrix

```text
Level: "minimal"
├── Stack/Heap Wipe: Executed immediately after last MIR read.
├── String Literals: Encrypted in .rodata, decrypted on heap allocation.
└── Performance Cost: < 2% CPU overhead, standard memory footprint.

Level: "balanced"
├── Stack/Heap Wipe: Non-elidable write barriers on drop/move.
├── Masking: 2-share XOR representation in separate heap/stack segments.
├── Register Scrubbing: Volatile zeroing of registers before return.
└── Performance Cost: 10%–30% CPU penalty on $crypt operations, 2x memory size for primitives.

Level: "paranoid"
├── Masking: 3+ dynamic shares with background memory re-masking.
├── Register Pinning: Value never leaves CPU registers; spill to stack rejected at compile-time.
├── Anti-Tracing: Inline cycle-count checks detecting single-stepping or kernel debuggers.
└── Performance Cost: Up to 500% slower for annotated blocks; intended strictly for small, critical operations.
```

---

## 6. Compiler Pipeline Architecture

rust-on-rails integrates changes across the AST parser, type checker, MIR optimization passes, and code generation backends:

```text
Source (.rs)
  │
  ▼
[rustc_parse]
  Recognizes `$` as postfix on types (T$crypt) and prefixes on items (fn$enclave, struct$crypt).
  │
  ▼
[rustc_hir / rustc_typeck]
  Enforces type-safety: Prevents implicit coercion of `$crypt` to unmasked primitives.
  Enforces strict borrow-checking: Moving a `$crypt` variable schedules an immediate zeroize.
  │
  ▼
[rustc_mir_transform]
  - SecureWipe Insertion: Injects mandatory wipe intrinsics at the exact liveness termination.
  - Constant-Time Enforcer: Prohibits branching on values labeled `$crypt`.
  │
  ▼
[rustc_codegen_llvm]
  ├─► Enclave Backend: Generates entry/exit stubs, clears registers upon boundary exit.
  ├─► Bare-Metal Backend: Strips standard OS runtime; links minimal boot/page-table harness.
  └─► Defended Backend: Emits additive XOR masking passes, decoy memory blocks, and RDTSC traps.
```

---

## 7. Implementation Roadmap

1. **Stage 1: Parser & AST Modifications**
   * Fork `rust-lang/rust`.
   * Update `compiler/rustc_parse` to parse `$` on types (`i32$crypt`), string literals (`"..."$crypt`), and item definitions (`fn$enclave`, `struct$crypt`).
2. **Stage 2: Type System & Borrow Checker Enforcement**
   * Implement compiler diagnostics preventing implicit dereferencing or unwrapped moves of `$crypt` data.
   * Add liveness hooks inside MIR to calculate the precise cycle a secret variable can be scrubbed.
3. **Stage 3: Software Defense Code Generation**
   * Write an LLVM transformation pass that splits `$crypt` allocas into multiple additive XOR shares.
   * Add non-elidable zeroization intrinsics using target-specific assembly instructions (`pxor`, non-temporal zero stores).
4. **Stage 4: Target Scopes (`fn$enclave`, `fn$baremetal`)**
   * Build target profiles automating Intel SGX SDK / AMD SEV runtime harness compilation.
   * Add bare-metal targeting scripts to package pure-Rust entry points into bootable micro-VM images.

### 7.1 Native Rust and rust-on-rails Source Compatibility

The same source project must be able to build with both the upstream/native Rust
compiler and the rust-on-rails compiler. This is a core compatibility requirement,
not an optional convenience. Code that does not use rust-on-rails-only security
semantics should remain ordinary, portable Rust.

Use Rust's existing conditional-compilation model (`cfg`, `cfg_attr`, and Cargo
features) as the compatibility mechanism rather than inventing a C-preprocessor
style `#ifdef` syntax. The rust-on-rails compiler should expose a documented
configuration predicate and/or target feature, for example:

```rust
#[cfg_attr(rust_on_rails, rust_on_rails::defended)]
fn process_request(input: &[u8]) -> Result<(), Error> {
    // One source file remains valid for native rustc and rust-on-rails.
    handle_request(input)
}
```

For syntax that cannot be represented as a valid native Rust attribute, provide a
stable compatibility macro, feature-gated module, or equivalent Rust-native
escape hatch so native `rustc` can exclude the rust-on-rails implementation at
parse time. The compiler must document the predicate, feature names, expansion
behavior, diagnostics, and behavior when the enhanced compiler is unavailable.
Compatibility tests must compile representative crates in both modes and verify
that native builds do not accidentally depend on rust-on-rails-only APIs.

### 7.2 Complete Rust and Cargo Interoperability

rust-on-rails must interoperate completely with Rust and the Cargo ecosystem. The
goal is not merely source-level similarity: supported Rust code and all Cargo
packages must be usable without requiring package authors to maintain a separate
ecosystem or forked dependency graph.

This requirement includes, subject to the target's explicitly documented limits:

* compatibility with Rust's language semantics, standard library, ABI, metadata,
  and stable compiler diagnostics;
* building, linking, testing, documenting, and publishing ordinary Cargo
  packages, workspaces, examples, benchmarks, build scripts, proc-macro crates,
  and mixed dependency graphs;
* support for crates.io packages, git/path dependencies, feature resolution,
  profiles, build scripts, native libraries, generated code, and transitive
  dependencies;
* compatible Cargo lockfiles, target selection, cross-compilation, incremental
  builds, and reproducible artifact/report generation; and
* explicit handling of `unsafe`, FFI, inline assembly, platform-specific code,
  and unsupported target assumptions, with clear diagnostics rather than silent
  semantic changes.

Security-enhanced behavior may require an opt-in feature or target profile, but it
must not silently alter the meaning of ordinary Rust packages. Every divergence
from upstream Rust or Cargo must be versioned, documented, tested against a
reference toolchain, and classified as supported, degraded, or unsupported. A
release cannot claim Rust/Cargo interoperability until a compatibility suite has
built and exercised representative real-world packages, including packages with
proc macros, native dependencies, workspace members, and feature combinations.

---

## 8. Extended Security Architecture and Implementation Contract

The following design adds explicit declassification, secret propagation, constant-time diagnostics, secure memory lifecycles, capability-based I/O, attestation-bound provisioning, compiler security reports, adversarial tests, reproducible benchmarks, and a target-specific guarantee matrix.

These features must share one model. A value has a confidentiality label, an ownership state, a storage policy, and an execution domain. A function has an effect summary describing disclosures, external operations, and timing-sensitive behavior. The compiler checks these properties together; a runtime library alone cannot reliably recover them after optimization.

### 8.1 Separate Confidentiality, Storage, and Execution

`$crypt` means that a value participates in confidentiality checking. It does not itself prove that the value is encrypted, masked correctly, or protected from a privileged attacker. A storage profile determines whether its representation is a wiped buffer, a shared representation, or a backend-specific register-only value. An execution target determines which components are trusted.

Internally, lower the surface syntax to concepts equivalent to:

```text
Confidentiality: Public | Secret(policy_id)
StoragePolicy: Wiped | Shared(profile_id) | RegisterOnly(profile_id)
ExecutionDomain: Host | DefendedHost | SgxEnclave | SnpGuest | BareMetal
FunctionEffects: disclosures + capabilities + constant_time_status
```

Distinct policy identifiers allow future separation of credentials, signing keys, and customer data. The first implementation should support one secret label plus public data. Multiple compartments require an explicit label lattice, permitted joins, and authority for crossing compartments; they must not be improvised through string comparisons.

### 8.2 Compiler Integration

1. **Parsing and expansion:** Parse qualifiers into dedicated AST nodes, preserve their spans, and validate parameters after macro expansion. Maintain Rust's existing `$` macro behavior inside macro syntax. Reject unknown qualifiers and contradictory options.
2. **HIR and type checking:** Preserve confidentiality in types and function signatures. Check trait selection, coercions, declassification authority, and domain transitions. Do not erase annotations before monomorphization.
3. **MIR analysis:** Compute data dependencies, control dependencies, function effects, and secret ownership. Attach security metadata to places, operations, and calls. Insert cleanup operations after borrow checking and before transformations that would erase required information.
4. **Optimization:** Require each relevant pass to preserve the security contract. Recompute or validate metadata after inlining, aggregate expansion, coroutine lowering, and copy propagation. Security metadata must affect legal transformations, rather than exist only as debug metadata that optimizers can discard.
5. **Backend lowering:** Translate abstract cleanup and approved constant-time operations through target-specific contracts. Use a late verification stage where machine allocation details are available. An LLVM IR pass cannot alone prove that register allocation introduced no spills.
6. **Link and packaging:** Check dependency summaries and target boundaries, produce a final artifact report, and bind it to the binary hash. LTO and external assembly require their own validation paths.

Introduce these phases incrementally behind an experimental feature gate. Compilation must fail when a required property lacks a supported implementation. An explicitly configured best-effort policy may permit a weaker property, but the report must state the downgrade.

---

## 9. Explicit Declassification

### 9.1 Problem and Semantics

Useful secret computations eventually release something: an authentication decision, a signature, or authorized decrypted content. An implicit conversion from secret to public hides this decision. rust-on-rails should require a named disclosure policy and an authority value at each release point.

The policy describes the permitted output, audience, purpose, and maximum release frequency where relevant. A reason string is audit metadata, not authorization. Creating authority requires application configuration or a trusted entry point; any function must not be able to mint unrestricted authority.

```rust
// Proposed APIs and syntax throughout these sections.
fn$defended verify_pin(
    candidate: i32$crypt,
    stored: &i32$crypt,
    permit: &ReleasePermit<AuthDecision>,
) -> bool {
    let matched: bool$crypt = ct_eq(candidate, stored);
    declassify(matched, permit, reason = "login decision")
}
```

This explicitly releases one decision. It does not make repeated guesses harmless. The surrounding authentication service must enforce rate limits and access policy; otherwise repeated authorized bits can reveal a credential.

### 9.2 Implementation

Implement `declassify` as a compiler-recognized operation with a policy-specific output type. Type checking verifies that the authority matches the label and release policy. MIR records a disclosure edge with source span, policy identity, caller effects, and output type. Ordinary casts, `Deref`, `From`, and trait coercions must not offer equivalent secret-to-public conversions.

A general raw-value release is permitted only by an explicit, appropriately privileged policy. Narrow operations such as releasing a comparison result or exporting ciphertext are preferred because they give reviewers a smaller output contract. A runtime check can enforce an audience or budget, but it cannot establish semantic facts such as whether arbitrary bytes are actually ciphertext. Cryptographic export must use approved primitives with documented preconditions.

Public outputs inherit normal public storage behavior. Scrubbing the source does not scrub the released copy. Diagnostics and reports must identify that boundary, including whether a released buffer may subsequently be logged or serialized.

### 9.3 Auditing and Failure

Compile-time disclosure records are deterministic and contain no secret payloads. Optional runtime records contain a policy ID, outcome category, and opaque request ID. Avoid recording secret-dependent lengths, user-provided reasons, or sensitive object addresses. Audit output itself needs a capability and a declared information-release policy.

If a permit expires or a release budget is exhausted, return a bounded public error that reveals only the approved failure category. Failure paths must retain secret cleanup obligations. The design must specify whether an attempted release consumes budget and make updates atomic under concurrent calls.

### 9.4 Acceptance Criteria

Reject unapproved return values, formatting, casts, and serialization. Accept authorized releases with a report entry. Test a helper that indirectly returns a secret, an expired permit, concurrent budget use, and a release followed by early error. Every accepted release must remain visible after inlining and LTO.

---

## 10. Secret Propagation and Type-System Rules

### 10.1 Propagation Model

For ordinary arithmetic and comparisons, the result label is the join of the operand labels. Public plus secret produces secret; a comparison of secrets produces a secret Boolean. Assigning public data into secret storage is allowed. Assigning secret data into public storage requires declassification.

Data flow alone is insufficient. A public assignment inside a branch controlled by a secret also leaks. Track a program-counter label during information-flow analysis: effects and assignments executed under secret control must satisfy that label. The constant-time subset should reject secret branches outright; the information-flow checker must still protect code outside that subset.

```rust
let key: u32$crypt = load_key();
let mixed = key ^ public_nonce; // inferred secret u32
let equal = ct_eq(mixed, expected); // inferred secret bool
println!("{}", mixed); // error: secret formatting requires disclosure

let mut public_flag = false;
if equal { public_flag = true; } // error: implicit flow and secret branch
```

Secret-dependent indexing, allocation sizes, exception behavior, and collection lengths require analysis too. A public `Option` discriminant may expose whether a secret computation succeeded. Either label the discriminant secret or release the success category under a declared policy.

### 10.2 Aggregates, References, and Generics

Track labels per field when feasible. A struct with a public ID and secret token may permit access to the ID without releasing the token. Applying `$crypt` to an entire struct labels every field unless a later language design explicitly permits mixed visibility. Tuple elements and enum discriminants need equivalent rules.

References must preserve the label of the referenced place. A reference to secret data does not become an ordinary `&T`, and taking a raw pointer must not erase the obligation. Secret containers need layouts that the compiler understands: `Vec<T$crypt>` protects elements, whereas a fully secret container must also protect metadata such as length if that information is sensitive.

Generic code is checked using confidentiality-aware constraints. Carry labels through associated types, closures, iterator adapters, and monomorphized implementations. Closure captures inherit labels; moving a secret into a closure transfers ownership and cleanup obligations. Coroutine captures become secret fields in the suspended state machine.

Dynamic dispatch requires a compatible security effect summary in the trait contract. Cross-crate summaries are part of compiler metadata and must be versioned. For dependencies with missing summaries, use a conservative boundary or reject the call under strict policies.

### 10.3 Traits and Escape Hatches

Do not automatically implement `Copy`, plaintext `Clone`, `Debug`, `Display`, serialization, or hashing for secret types. A redacted debug representation may be available if it emits a fixed public marker. Secret duplication must be explicit and creates an additional tracked owner. Constant-time equality returns a secret choice rather than an ordinary branchable Boolean.

`unsafe` does not silently declassify a value. Operations that expose representation through FFI, inline assembly, unions, raw pointers, or transmutation require an explicit security boundary declaration. Reports list these boundaries as assumptions. The compiler cannot prove confidentiality of arbitrary unsafe code or external implementations without an additional verification contract.

### 10.4 Implementation and Validation

Use the type checker for explicit conversions and a flow-sensitive MIR analysis for inferred labels and implicit flows. Model aliasing through borrow-checked places; treat unknown writes conservatively. Solve recursive call summaries to a fixed point. Bound analysis complexity and reject unsupported cases with a useful diagnostic rather than guessing a public label.

Compile-fail tests should cover generics, trait objects, closures, enum discriminants, raw pointers, macro expansions, and cross-crate helpers. Positive tests should demonstrate access to genuinely public fields and authorized narrow releases. This first milestone establishes confidentiality checking before experimental masking is introduced.

---

## 11. Constant-Time Diagnostics and Approved Primitives

### 11.1 Scope of the Claim

Define constant time relative to a declared observation model: for fixed public inputs, control flow, memory addresses, and approved instruction behavior must not depend on secrets. Input sizes are public only when the API says so. Secret sizes require fixed-size storage, padding, or an approved length disclosure.

This contract is not a promise of immunity to every physical or microarchitectural channel. Target assumptions, instruction behavior, runtime services, and speculative execution mitigations belong in the report. Intel's guidance describes timing risks and mitigations that depend on implementation and platform details ([Intel timing guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)).

### 11.2 Diagnostics

Reject or require an explicit supported primitive for:

- Branches, `match` discriminants, or early returns controlled by a secret.
- Loop termination and iteration counts dependent on a secret.
- Loads and stores whose addresses depend on a secret, including table lookups.
- Allocation sizes and external call counts that depend on a secret.
- Operations with unsupported operand-dependent timing on the selected CPU, such as certain division paths.
- Calls without a compatible constant-time contract, including panic paths generated by bounds or overflow checks.

Diagnostics should show the secret source, the dependency path, the observable operation, and a supported rewrite. Avoid claiming that replacing `if` with a ternary expression fixes timing: the backend may produce a branch or a variable-time instruction.

### 11.3 Compiler and Backend Implementation

Perform initial checks on MIR after monomorphization so generic operations and implicit checks are visible. Introduce dedicated operations for constant-time selection, equality, and approved cryptographic calls. Preserve their semantics through optimization using backend-supported lowering rather than relying on source patterns.

Validate optimized IR and final machine code for the supported subset. A machine verifier must reconstruct secret dependencies and inspect branches, addresses, and selected instructions. Where this analysis is incomplete, report the limitation and reject strict certification. Debug information and instruction scanning alone are insufficient proofs of data independence.

Maintain a registry of approved primitive implementations keyed by source or binary identity, compiler configuration, target architecture, and required CPU features. Approval for one build does not automatically apply to a replacement dependency or a different backend. Record nonce requirements and other cryptographic preconditions separately from timing status.

### 11.4 Testing

Combine negative compiler tests, machine-code review, and repeated timing measurements across contrasting secret classes with identical public inputs. Statistical timing tests can expose regressions but cannot prove absence of leakage. Include cache-address traces where practical and rerun after compiler, target-feature, and crypto dependency changes.

---

## 12. Secure Memory Lifecycle and Storage Backends

### 12.1 Ownership and Cleanup Contract

A secret allocation has one owner or an explicit shared ownership protocol. The compiler tracks initialization, reads, outstanding borrows, moves, and destruction. Cleanup occurs after the last possible access, including exceptional paths, rather than at an assumed exact CPU cycle. Static liveness identifies safe program points; it does not schedule wall-clock time.

Prefer moving an owning handle over copying payload bytes. When a physical move is necessary, initialize the destination successfully before scrubbing the source. Do not wipe aliases still used by the destination. Partial initialization, partial moves, and custom destructors need field-level cleanup state. Cleanup must not precede a destructor that legitimately reads the secret.

An ordinary Rust `Drop` implementation is insufficient as the sole guarantee: destructors may be skipped, including through forgetting values or aborting a process ([Rust Reference: destructors](https://doc.rust-lang.org/reference/destructors.html)). rust-on-rails must define stronger restrictions for strict managed-secret scopes and clearly delimit cases where cleanup remains best effort.

### 12.2 Non-Elidable Wiping

Introduce an internal operation such as `crypt_wipe(ptr, len, policy)` with specified observable effects. Lower it to a supported secure-erasure implementation, and verify that stores survive optimization. Prevent transformations from deleting required writes, shortening their ranges, or moving them before the final access.

Wipe owned allocation capacity where initialized secret bytes may have existed, not merely the current logical length. Reallocation must wipe the old allocation before release. Secret storage should use a dedicated allocator with correct alignment, guard-page support where available, and no unwiped reuse of retained blocks. Allocator metadata must never contain secret payloads.

Zeroing memory is a bounded software property. It does not prove removal of historical copies in caches, swap, snapshots, device buffers, or storage. Volatile writes alone do not establish all required optimization and hardware guarantees; the implementation needs a backend contract and emitted-code checks. Cache flushing and non-temporal stores must be justified per target rather than assumed to strengthen every wipe.

### 12.3 Temporary Values and Register State

Track compiler-generated temporaries, call argument staging, spills, return slots, vector lanes, and inlined intermediate results. A register-only policy needs a narrowly supported ABI and a check after register allocation. Reject builds that spill protected payloads to memory under that policy. Context switching, interrupts, and OS-managed register saving remain outside a software-only guarantee against the OS.

Clearing all registers on return is not a valid blanket rule: return values and ABI-preserved state may still be live. Clear only dead secret-bearing registers and permitted scratch state through backend-aware code generation. Hardware enclave asynchronous exits require the platform's state-save model to be included in the trust analysis.

### 12.4 Unwinding, Cancellation, and Abnormal Exit

- **Normal return and handled error:** Insert cleanup on every owned exit path.
- **Panic unwinding:** Support cleanup landing pads and panic messages that do not format secrets. Cleanup must not panic or allocate unpredictably.
- **Async cancellation:** Store secrets in tracked future fields and clean initialized fields when the future is dropped. Detached tasks and retained futures continue to own secrets until explicitly shut down.
- **Forget, leaks, and ownership cycles:** Reject supported leak operations in strict secret scopes. Unchecked dependencies and unsafe code must be listed as assumptions; do not promise universal detection of leaks.
- **Abort, forced kill, power loss, and host failure:** Do not claim guaranteed execution of cleanup. A best-effort abort hook may help selected cases, but it cannot handle arbitrary termination.

Strict scopes should reject unsupported combinations, such as requiring guaranteed unwind cleanup with a build that only aborts. For termination resistance, rely on platform isolation and key lifecycle where available, with precise residual-risk statements.

### 12.5 Masking and Rotation

Two- or three-share XOR storage can reduce exposure to a partial memory observation. It cannot protect against an attacker who reads every share or observes reconstruction. XOR sharing is not encryption against an all-memory reader, and is not the same as arithmetic additive sharing. Nonlinear computation on shares requires specialized algorithms and randomness; splitting an allocation does not automatically create secure masked execution.

Use a cryptographically suitable randomness provider for share initialization and refresh. Fail on unavailable entropy when masking is mandatory. Treat secret literals as build-time exposure: encrypting a literal with a key shipped in the same binary provides obfuscation, not protection against reverse engineering. Strong key secrecy requires external provisioning.

For refresh, construct a new consistent share set under a lock or versioned protocol, publish it atomically, retire readers of the old set, and wipe old shares before freeing them. A deadline such as `rotate_ms = 50` is a requested interval, not a guaranteed schedule under a hostile OS. Define delayed-refresh behavior and avoid unsynchronized background writes to borrowed data.

Decoy allocations and anti-debug timing checks are optional experiments. Measure their cost and false positives. They must not be prerequisites for the core type-system contract, and must not be reported as reliable detection of a privileged observer.

---

## 13. Capability-Based I/O and Host Boundaries

### 13.1 Capability Model

Defended code should receive explicit handles for external effects rather than ambient access to files, networking, logging, clocks, entropy, or host calls. A capability identifies permitted operations and scope: an approved peer, a file region, a bounded audit sink, or a randomness source with defined trust assumptions.

```rust
fn$defended sign_request(
    request: &[u8],
    key: &SigningKey$crypt,
    entropy: &EntropyCapability,
    output: &NetworkCapability<ApprovedPeer>,
    permit: &ReleasePermit<Signature>,
) -> Result<(), PublicError> {
    let signature = approved_sign(key, request, entropy)?;
    let published = declassify(signature, permit, reason = "signed response");
    output.send(&published)
}
```

Capabilities do not themselves make secret bytes public. Sending a secret still requires a release policy or a dedicated encrypted-export operation. Operation timing, packet size, and errors may disclose information and must fit the boundary contract.

### 13.2 Static Effect Checking

Attach an effect summary to each function and propagate it through calls. Reject ambient `std::fs`, socket, logger, clock, and syscall access in checked code unless routed through an approved adapter. Check transitive dependencies, closures, and trait methods; missing summaries are not treated as effect-free.

Lower enclave-to-host calls into explicit marshaling stubs. Validate host-supplied lengths, pointer ranges, integer conversions, and returned status codes. Copy untrusted inputs into owned storage before validation when concurrent host modification could invalidate assumptions. Avoid returning pointers into secret memory or trusting a host-managed clock for security deadlines.

### 13.3 Runtime Enforcement and Platform Mapping

Construct capabilities at trusted application entry points and attenuate them when passing into less-privileged code. Bind a network handle to an authenticated peer identity, not merely a mutable hostname or socket address. Define cloning and revocation explicitly, including races with in-flight operations.

On a standard OS, static effect checks constrain cooperating checked code. Unchecked native code or a compromised kernel can bypass software-only restrictions. Strong runtime enforcement needs an appropriate isolation boundary: a sandbox with an honest kernel, an enclave broker protocol, or microkernel capabilities. Bare metal alone does not supply such a capability system; it must be implemented in the runtime or monitor.

Test denied effects through indirect calls and dependencies, forged handles, oversized host responses, peer substitution, and revocation during I/O. Reports should distinguish statically checked effects from platform-enforced permissions.

---

## 14. Attestation-Bound Secret Provisioning

### 14.1 Target-Specific Trust Boundaries

Replace the idea that `fn$enclave` alone creates equivalent SGX and SEV-SNP isolation with distinct backends. SGX isolates an enclave within a process. SEV-SNP protects a guest VM from its host under the platform threat model; the guest kernel and guest software remain part of the relevant trusted computing base. A function annotation selects placement and entry stubs, but provisioning and deployment establish the actual protected environment.

For SGX, produce an enclave artifact with explicit entry and host-call interfaces. For SNP, package the workload and required guest components into a measured VM image. A guest runtime cannot claim that a function is isolated from a compromised guest kernel simply because the VM is protected from its host.

### 14.2 Provisioning Protocol

Use a remote verifier and key service separate from the untrusted host:

1. The service creates a fresh, single-use challenge and identifies a release policy.
2. The protected workload generates an ephemeral channel key inside the protected boundary.
3. The workload requests evidence binding a hash of the challenge, channel public key, policy identifier, and protocol context into the platform's supported report-data field.
4. The verifier checks evidence authenticity, certificate chains, measurement allowlists, platform security status, debug configuration, and the challenge binding.
5. The service establishes an authenticated encrypted channel whose peer proves possession of the bound private key.
6. The service releases a scoped, preferably short-lived key only for the authorized workload and purpose. Store it directly in managed secret storage.

Use an established cryptographic channel protocol with documented evidence binding. A signed report alone does not authenticate a later unrelated TLS connection. Bind protocol version, service identity, and workload role to prevent cross-protocol substitution.

The Linux SNP guest interface exposes report requests and certificate retrieval, but the verifier must still implement policy evaluation and channel binding ([Linux SEV guest API](https://kernel.org/doc/html/next/virt/coco/sev-guest.html)). Define distinct evidence adapters for each platform rather than assuming identical claims.

### 14.3 Freshness, Rollback, and Revocation

Reject reused or expired challenges using verifier-controlled state and time. Enforce a minimum approved workload version and reject superseded measurements when policy requires it. Fresh attestation does not itself prevent a workload from consuming rolled-back application data: persistent state needs a remote version authority, authenticated monotonic state, or another explicitly trusted freshness mechanism.

Revocation prevents future issuance and renewal. Immediate withdrawal from an already running workload requires a separate enforcement design; wiping a key on receipt of revocation is insufficient when the host can suppress delivery. Prefer short leases enforced by a trusted service where the target cannot supply trusted time.

Keep provisioning failures public and bounded. Do not expose private material in evidence logs. Define offline behavior explicitly: fail closed for policies requiring online freshness, or document the weaker guarantees of cached authorization.

### 14.4 Packaging and Tests

Bind approved measurements to the actual measured artifact and its boot/runtime dependencies. Sign release policy metadata and record the relationship between build report, binary, enclave or VM image, and expected measurement. The remote verifier must use the platform measurement, not trust a hash asserted by the workload.

Test replayed challenges, a substituted channel key, unapproved measurements, debug deployments, stale security status, old workload versions, revoked credentials, and rolled-back state. Separate simulation tests from tests on supported hardware; simulated evidence cannot certify production attestation.

---

## 15. Compiler Security Reports

### 15.1 Report Contents

Produce both a human-readable report and versioned JSON for automated checks. Proposed invocation: `rust-on-railsc --emit-security-report=report.json`. Include:

- Compiler, runtime, backend, policy, target, and dependency versions; optimization and LTO settings.
- Hashes of the final executable and packaged protected artifact, plus the applicable measurement derivation.
- Secret declarations, inferred secret values, aggregate fields, and source locations.
- Requested and realized storage policies, including unsupported or downgraded requests.
- Cleanup points for normal, exceptional, and cancellation paths, with limits on abrupt termination.
- Declassification edges, their authority policies, and public output types.
- Capability effects, host interfaces, unsafe boundaries, FFI calls, and external assembly assumptions.
- Constant-time verification status, covered functions, primitive identities, target assumptions, and gaps.
- Spill and register-cleanup findings for the supported backend subset.

Use statuses such as `enforced`, `verified-for-supported-subset`, `best-effort`, `assumed`, and `unsupported`. Do not collapse them into a green security score.

### 15.2 Collection and Artifact Binding

Collect records as compiler passes make decisions, then reconcile them after optimization and linking. A declaration that disappears through optimization still needs an explanation; a new spill needs a record associated with its originating secret. Report both source-level obligations and final-artifact findings.

Generate the executable hash only after final byte-changing steps. Store the report outside the executable to avoid a self-referential hash. Sign a manifest binding report and artifact hashes when authenticity is needed. For reproducibility, separate timestamps and local paths from deterministic semantic content.

Reports must not include literal secret contents, reconstructed values, production keys, or raw memory dumps. Source names and paths may themselves be sensitive; provide a redacted report mode with stable identifiers. Store diagnostic artifacts under access controls appropriate to the project.

### 15.3 CI Policy

Allow a policy file to require complete disclosure listings, no unsupported register-only operations, approved dependency identities, and zero undeclared host effects. Compare semantic reports across builds and flag new releases or trust assumptions. A report is evidence about a specified build; signing it does not convert assumptions into verified properties.

---

## 16. Adversarial Security Test Suite

### 16.1 Test Layers

**Language tests:** Use compile-pass and compile-fail cases for labels, implicit flows, authority, capabilities, and generic behavior. Include macro expansion, cross-crate calls, and diagnostics with accurate spans.

**MIR tests:** Check secret ownership and cleanup obligations around early returns, panics, partial moves, nested aggregates, and coroutine cancellation. Prefer properties such as coverage of all owned exit paths over fragile instruction-by-instruction snapshots.

**Artifact tests:** Build release configurations with and without LTO. Inspect final binaries, object files, metadata, and available debug artifacts for synthetic plaintext sentinels. Check required wipe operations and supported machine-level constant-time properties. Record compiler and target configuration for each finding.

**Runtime tests:** Use deterministic checkpoints and instrumented allocation in an isolated harness to inspect managed buffers before and after cleanup. Verify old allocations during reallocation and move staging. Instrumentation may change behavior, so also validate representative optimized builds.

**Hardware tests:** Exercise enclave or guest boundaries, host-call validation, attestation, and supported platform failure paths. Identify results produced on physical hardware separately from mocks.

### 16.2 Memory and Exposure Experiments

Use generated synthetic secrets with unique markers; never use production credentials. Sample process memory, enabled crash dumps, and controlled swap or snapshot artifacts where the test environment permits. Search logs and diagnostic output for accidental disclosure. Define exactly when the marker is expected to be observable and when it must have been erased.

A missing marker is not proof that all secret representations are absent. Shares, encoded values, partial copies, and transient register contents need representation-aware checks. Report the observation coverage and sampling windows. For defended host mode, deliberately show that an observer reading all shares can reconstruct the secret; this validates the stated threat limitation.

Do not implement a covert anti-debugger bypass as a prerequisite for testing. Use authorized harnesses with explicit observation points and record how instrumentation affects the experiment.

### 16.3 Fuzzing and Concurrency

Fuzz qualifier parsing, policy loading, boundary marshaling, report decoding, and evidence adapters with bounded resources. Exercise share refresh while readers are active, permit budgets under concurrency, cancellation during provisioning, and allocator exhaustion. Use race and memory-safety tooling where supported, while acknowledging when instrumentation cannot run inside a selected target.

### 16.4 Release Gates

Require passing confidentiality and cleanup tests for supported configurations, no unexplained plaintext retention in managed buffers, a completed target report, and successful attestation-negative tests for production protected targets. Timing regression results need review thresholds and repeatability rules. New compiler or LLVM versions must requalify affected backend guarantees.

Maintain a regression case for every confirmed leak. Publish test limitations alongside results. Neither binary scans nor timing tests alone justify a claim of complete confidentiality.

---

## 17. Defense Benchmarks and Performance Calibration

### 17.1 Replace Estimates with Measurements

The percentages in Section 5 are planning hypotheses, not measured budgets or guarantees. A release must provide measured results per workload, target, CPU, compiler configuration, and defense profile. A register-only profile may fail to compile under pressure rather than slow down gracefully; report that outcome explicitly.

Benchmark an ordinary Rust baseline, confidentiality checking with managed wiping, shared storage variants, rotation variants, and each supported protected deployment. Keep algorithms, public inputs, optimization settings, and correctness criteria comparable. Use externally provisioned synthetic keys for attestation workloads so literal obfuscation does not distort the comparison.

### 17.2 Workload Set

- Fixed-width arithmetic and comparisons, including increasing register pressure.
- Fixed-size secret buffers, moves, allocation, reallocation, and cleanup.
- Approved signing, authenticated encryption, and verification operations.
- Long-lived key stores with multiple readers and share rotation.
- Boundary calls of varying public payload sizes and batching strategies.
- End-to-end authentication or signing requests under concurrent load.
- Error handling, coroutine cancellation, and shutdown with many live secrets.

Separate steady-state request cost from startup, remote attestation, and provisioning latency. Measure idle rotation cost as well as per-request overhead. End-to-end latency matters when a microbenchmark's fast primitive sits behind expensive boundary calls.

### 17.3 Method and Metrics

Record latency distributions, throughput, peak and steady resident memory, allocation counts, binary size, and refresh latency. Collect CPU cycles and cache counters where the platform exposes them reliably. Capture baseline variance and repeated samples; record CPU features, firmware, mitigation configuration, OS or guest image, affinity, and power policy.

Report slowdown as `(protected_time / baseline_time - 1) * 100%` for comparable timed operations, and show absolute times too. Use confidence intervals or another stated uncertainty method. Prevent dead-code elimination and verify outputs without including verification work in the timed operation unless it belongs to the workload.

Performance gates should compare against a stable machine and a versioned baseline. Investigate regressions exceeding agreed tolerances; do not reduce security guarantees automatically to pass a benchmark. A timing tripwire's false-positive rate under load, virtualization, and scheduling interruptions is a separate metric.

### 17.4 Configuration Resolution

Define precedence among crate defaults, item overrides, and deployment policy. A deployment policy may require stronger protection or reject a weaker item request. Record the fully resolved policy in the report. Existing `[profile.release.crypt]` keys are proposed custom Cargo integration, not accepted stock Cargo settings; implement a wrapper or Cargo extension and validate all keys before claiming support.

Begin with a small supported profile set: managed wipe, experimental shared storage, and a constrained register-only subset. Avoid offering numerous knobs whose combinations have no tested semantics.

---

## 18. Guarantee Matrix and Threat-Model Boundaries

### 18.1 Definitions

**Enforced** means checked code cannot compile or run through an approved path while violating the stated property, subject to listed trusted components. **Verified subset** means validation applies only to specified constructs and targets. **Best effort** means a mitigation reduces exposure without establishing the property against the stated adversary. **Unsupported** means the target cannot supply the property.

These are planned acceptance categories, not a claim that the current project has implemented them. A build report may claim a category only after its implementation and validation requirements pass.

| Property | Defended standard OS | SGX enclave | SEV-SNP guest | Bare metal / seL4 deployment |
| :--- | :--- | :--- | :--- | :--- |
| No implicit secret-to-public conversion | Enforced in checked code | Enforced in checked code | Enforced in checked code | Enforced in checked code |
| Declared I/O effects | Static checking; runtime enforcement depends on an honest isolation layer | Checked interfaces; host responses remain untrusted | Checked interfaces; guest OS participates in enforcement | Requires runtime or microkernel capability design |
| Cleanup on supported normal and unwind paths | Enforced for managed storage and supported paths | Same software obligation inside enclave | Same software obligation inside guest | Depends on supported allocator and exception model |
| Cleanup after arbitrary termination | Unsupported as a software guarantee | Not a universal erasure guarantee | Not a universal erasure guarantee | Not a universal erasure guarantee |
| Confidentiality against a malicious host kernel | Unsupported; masking is best effort against limited observation | Hardware boundary under platform assumptions; side channels remain | Protects guest from host under platform assumptions, not from guest kernel | No conventional host OS on true bare metal; monitor, firmware, DMA, and physical access require analysis |
| Constant-time execution | Verified subset and target assumptions | Verified subset; enclave isolation does not establish it | Verified subset; VM encryption does not establish it | Verified subset and target assumptions |
| Register-only secrets against the OS | No-spill verification is possible for a subset; OS context capture remains | Needs backend and enclave state-save analysis | Guest context saving remains inside guest trust boundary | Interrupt and context-save policy must be designed |
| Remote attestation-bound provisioning | Requires an additional trustworthy attesting boundary | Platform evidence plus external verifier policy | Platform evidence plus external verifier policy | Requires an explicit measured-boot/attestation platform; seL4 alone is insufficient |
| Fresh persistent state | Requires external or trusted monotonic authority | Not supplied by enclave isolation alone | Not supplied by VM protection alone | Requires a platform-specific authority |
| Availability against a hostile host | Unsupported | Host can deny service | Host can deny service | Depends on deployment; hardware and external services can still fail |

### 18.2 Target Corrections to the Introductory Examples

Intel explicitly excludes general side-channel protection from SGX's design ([Intel SGX security properties](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/linux-overview.html)). Therefore an enclave example must not imply that encryption solves timing, access-pattern, interface, or speculative-execution leakage.

`fn$baremetal` expresses placement intent. It cannot strip OS dependencies from arbitrary code or generate a safe boot environment automatically. The build must reject unsupported libraries and provide a target-specific allocator, interrupt model, page tables, device policy, and boot chain. A seL4 deployment includes a microkernel and its configured system components; it is a distinct isolation design from running without a kernel.

`fn$defended` supplies checked confidentiality rules and selected software mitigations. It cannot create a zero-trust boundary against the OS that schedules it and observes its memory. Spreading shares across pages does not prevent an all-memory reader from collecting them. Cycle-count checks cannot reliably distinguish debugging from scheduling delays, and a malicious host can manipulate the execution environment.

Promises such as “never written to DRAM,” “all registers zeroed,” “wiped instantly,” and “guaranteed wipe on Drop” must be replaced by build-specific claims about supported code paths and observable storage. Encrypted literals with bundled decryption keys are obfuscation. Strong credentials should enter through trusted input or attestation-bound provisioning.

### 18.3 Trusted Computing Base Inventory

Every target report must list the compiler and backend, secret runtime, approved cryptographic libraries, allocator, boundary adapters, provisioning verifier, hardware and firmware assumptions, and any kernel or monitor trusted by that deployment. Include unsupported unsafe code and dependency summaries as explicit gaps.

The system can offer different assurance levels, but it must never silently inherit the strongest level advertised by a qualifier name. Hardware availability, debug mode, backend support, and actual packaging decide the realized protection.

---

## 19. Delivery Plan, Dependencies, and Completion Criteria

### Milestone A: Specify and Enforce Confidentiality

Finalize public/secret label semantics, approved release policies, and effect summaries. Implement parser nodes, confidentiality-aware types, explicit declassification, trait restrictions, and cross-crate metadata. Deliver compile-pass/fail tests and an initial source-level report. Completion means secret data cannot enter ordinary outputs through supported checked constructs without a declared release.

### Milestone B: Managed Storage and Cleanup

Implement fixed-size secret buffers and owning handles before attempting arbitrary secret aggregates. Add allocation tracking, non-elidable cleanup operations, move semantics, unwind paths, and coroutine cancellation. Qualify a small backend set with optimized artifact checks. Completion means all supported managed-storage exit paths have validated cleanup, with abrupt termination limitations stated.

### Milestone C: Constant-Time Subset and Capabilities

Implement dependency checks for branches and addresses, a small primitive registry, capability adapters, and transitive effect analysis. Integrate backend validation for a documented subset. Completion means unsupported operations fail closed in strict mode and accepted code has a report naming its verification coverage.

### Milestone D: Protected Deployment and Provisioning

Deliver one hardware target end to end before adding the second. Implement artifact packaging, entry interfaces, evidence generation, remote verification, channel binding, freshness policy, and key lifecycle. Completion requires real-hardware negative tests and an accurate target trust inventory, not only successful simulation.

### Milestone E: Experimental Masking and Rotation

Add shared storage only after ownership and cleanup are reliable. Specify partial-observation assumptions and approved computations on shares. Implement synchronized refresh, entropy failure handling, and retirement cleanup. Completion requires reconstruction correctness under concurrency, explicit all-shares attack tests, and measured resource costs. Keep anti-tracing and decoy behavior opt-in until their utility is demonstrated.

### Milestone F: Release Evidence and Performance Budgets

Produce final-artifact reports, signed manifests where needed, adversarial regression tests, and reproducible workload benchmarks. Publish which target/profile combinations meet each matrix entry. Completion means a release can be reviewed from its code, policy, artifact identities, test evidence, and measured costs without relying on unsupported marketing claims.

### Cross-Cutting Engineering Decisions

- Version language syntax, runtime ABI, effect metadata, and report schema independently but document compatible combinations.
- Keep ordinary Rust code compatible wherever security semantics do not require a restriction. A public-to-secret conversion should be easy; a secret-to-public conversion should be explicit.
- Treat build scripts, procedural macros, dependency artifacts, and signing tools as build-time trust inputs. Runtime confidentiality checking does not protect secrets embedded in source from a compromised build machine.
- Require a threat-model review whenever a new target, primitive, FFI boundary, or storage policy is added.
- Track unsupported constructs as explicit issues with diagnostics and acceptance tests. Do not silently weaken a guarantee to accommodate them.

### Reference Basis

The external references above establish platform and language limitations. The rust-on-rails syntax, analyses, runtime interfaces, protocols, and delivery milestones are proposed designs. Before implementation, pin the upstream Rust revision and backend versions, then write design notes against their actual internal APIs. A fork-wide security claim requires validation of the selected implementation, not merely consistency with this specification.
