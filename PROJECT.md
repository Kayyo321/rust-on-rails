The nested ````rust` blocks inside the outer code block caused the markdown renderer to close the block prematurely.

To keep the entire document in one contiguous, copyable box, the outer wrapper is expanded to 4 backticks (` `markdown ````), which lets all internal 3-backtick code blocks nest cleanly without breaking out.

```markdown
# Crypt-Rust: Architecture & Specification Document

**Project Codename:** `Crypt-Rust`  
**Base Upstream:** `rust-lang/rust`  
**Classification:** Confidential Systems Compiler & Adversarial Runtime  
**Core Syntax Marker:** `$` (Unified Confidentiality & Target Modifier)

---

## 1. Executive Summary & Philosophy

Current confidential computing frameworks rely on fragmented libraries, manual zeroization calls, and heavy foreign-function interface (FFI) plumbing. 

**Crypt-Rust** elevates data privacy and isolation into first-class language mechanics. By utilizing the `$` sigil as an explicit syntactic qualifier for types, literals, data structures, functions, and target domains, Crypt-Rust enables developers to write code that survives in hostile environments under a **Zero-Trust Host Model**—where the underlying operating system, supervisor layers, and memory buses are treated as untrusted or actively compromised.

---

## 2. Syntax & The `$` Unified Qualifier System

In standard Rust, `$` is reserved strictly for macro transcription. Crypt-Rust reclaims `$` in normal code contexts, utilizing it as the universal compiler directive for privacy constraints, target isolation, and memory lifecycles.

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

Crypt-Rust provides three primary execution targets, selectable per item via the `$` qualifier or globally across compilation crates:

| Target Directives | Threat Model | Isolation Mechanism | Trade-Off |
| :--- | :--- | :--- | :--- |
| **`fn$enclave`** / **`struct$enclave`** | Protects against Ring 0 rootkits, malicious OS, physical memory scrapers. | Hardware-enforced encryption (Intel SGX, AMD SEV-SNP). | Boundary transition overhead; hardware vendor lock-in. |
| **`fn$baremetal`** / **`struct$baremetal`** | Eliminates host OS attack surface entirely. | Runs directly on bare metal or an seL4 microkernel without an OS. | No standard OS APIs; requires direct device/memory handling. |
| **`fn$defended`** / **`struct$crypt`** | Mitigates memory dumps, Cheat Engine, and cold-boot dumping on standard OS. | Software-level additive masking, register pinning, anti-tracing tripwires. | Measurable CPU and cache overhead; cannot permanently stop dedicated Ring 0 debuggers. |

---

## 4. User-Space Software Defense: Developer Guide & Practical Examples

When running in an environment without hardware enclaves or bare-metal access (such as a client desktop running Windows or Linux), the programmer can activate **User-Space Software Defense**. 

Because this incurs substantial CPU and memory overhead, Crypt-Rust gives the developer full control over when and how these defenses are deployed.

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

Crypt-Rust integrates changes across the AST parser, type checker, MIR optimization passes, and code generation backends:

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

```