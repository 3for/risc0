The RISC Zero zkVM is a RISC-V virtual machine that produces [zero-knowledge
proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof) of code it executes.
By using the zkVM, a cryptographic [receipt](receipts), which can be verified
by anyone, is produced as the proof of the correct execution of the zkVM's guest
code. No additional information about the code execution (such as, for example,
the inputs provided) is revealed by publishing the [receipt](receipts).

In addition to [our reference documentation on
docs.rs](https://docs.rs/risc0-zkvm), we have additional (non-reference)
resources for using our zkVM that you may also find helpful, especially if
you're new to the RISC Zero zkVM. These include:

* Our [Hello World](https://github.com/risc0/risc0/tree/main/examples/hello-world) demo -- a minimal zkVM application that works out-of-the-box.
* Our [zkVM Tutorial](https://github.com/risc0/risc0/blob/v0.19.0/examples/hello-world/tutorial.md), which walks you through writing your first zkVM project.
* The [`cargo risczero` tool](https://crates.io/crates/cargo-risczero). It
includes a `new` command which generates code for building and launching a zkVM
guest and a guidance on the most common locations for modifying host and guest
code in a project.
* The [examples
folder](https://github.com/risc0/risc0/tree/main/examples), which contains
various examples using our zkVM.
* [This clip](https://youtu.be/cLqFvhmXiD0) from our presentation at ZK Hack III
gives an overview of the RISC Zero zkVM. [Our YouTube
channel](https://www.youtube.com/@risczero) has many more videos as well.
* We track zkVM issues with known workarounds using the [rust guest
  workarounds](https://github.com/risc0/risc0/issues?q=is%3Aissue+is%3Aopen+label%3A%22rust+guest+workarounds%22)
  GitHub tag. If you're having problems running your code in the zkVM, you can
  see if there's a workaround, and if you're using a workaround, you can track
  when it gets resolved to a permanent solution.
* And more on [the RISC Zero developer website](https://dev.risczero.com/)!

# Crate Feature Flags

The following [crate feature flags](https://doc.rust-lang.org/cargo/reference/features.html) are available.

Note that in order to use `risc0-zkvm` in the guest, you must disable the "prove" feature by setting `default-features = false`.

| Feature          | Target(s)         | Implies            | Description                                                                                                                                                  |
| ---------------- | ----------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| client           | all except rv32im | std        | Enables the client API.                                                                                                                                      |
| cuda             |                   | prove, std | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                                         |
| disable-dev-mode | all except rv32im |                    | Disables dev mode so that proving and verifying may not be faked. Used to prevent a misplaced `RISC0_DEV_MODE` from breaking security in production systems. |
| metal            | macos             | prove, std | Enables Metal GPU acceleration for the prover.                                                                                                               |
| prove            | all except rv32im | std        | Enables the prover, incompatible within the zkvm guest.                                                                                                      |
| std              | all               |                    | Support for the Rust stdlib.                                                                                                                                 |
