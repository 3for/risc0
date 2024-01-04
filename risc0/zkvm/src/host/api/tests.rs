// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::Command,
    thread,
};

use anyhow::Result;
use risc0_zkvm_methods::{
    multi_test::MultiTestSpec, MULTI_TEST_ELF, MULTI_TEST_ID, MULTI_TEST_PATH,
};
use tempfile::{tempdir, TempDir};
use test_log::test;

use super::{Asset, AssetRequest, ConnectionWrapper, Connector, TcpConnection};
use crate::{
    recursion::SuccinctReceipt, ApiClient, ApiServer, ExecutorEnv, Groth16Receipt, Groth16Seal,
    InnerReceipt, ProverOpts, Receipt, SegmentReceipt, SessionInfo, VerifierContext,
};

struct TestClientConnector {
    listener: TcpListener,
}

impl TestClientConnector {
    fn new() -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind("127.0.0.1:0")?,
        })
    }
}

impl Connector for TestClientConnector {
    fn connect(&self) -> Result<ConnectionWrapper> {
        let (stream, _) = self.listener.accept()?;
        Ok(ConnectionWrapper::new(Box::new(TcpConnection::new(stream))))
    }
}

struct TestClient {
    work_dir: TempDir,
    client: ApiClient,
    addr: SocketAddr,
    segments: Vec<Asset>,
}

impl TestClient {
    fn new() -> Self {
        let connector = TestClientConnector::new().unwrap();
        let addr = connector.listener.local_addr().unwrap();
        let client = ApiClient::with_connector(Box::new(connector));
        Self {
            work_dir: tempdir().unwrap(),
            client,
            addr,
            segments: Vec::new(),
        }
    }

    fn get_work_path(&self) -> PathBuf {
        self.work_dir.path().to_path_buf()
    }

    fn execute(&mut self, env: ExecutorEnv<'_>, binary: Asset) -> SessionInfo {
        with_server(self.addr, || {
            let segments_out = AssetRequest::Path(self.get_work_path());
            self.client
                .execute(&env, binary, segments_out, |_info, asset| {
                    self.segments.push(asset);
                    Ok(())
                })
        })
    }

    fn prove(&self, env: ExecutorEnv<'_>, opts: ProverOpts, binary: Asset) -> Receipt {
        with_server(self.addr, || self.client.prove(&env, opts, binary))
    }

    fn prove_segment(&self, opts: ProverOpts, segment: Asset) -> SegmentReceipt {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.prove_segment(opts, segment, receipt_out)
        })
    }

    fn lift(&self, opts: ProverOpts, receipt: Asset) -> SuccinctReceipt {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.lift(opts, receipt, receipt_out)
        })
    }

    fn join(&self, opts: ProverOpts, left_receipt: Asset, right_receipt: Asset) -> SuccinctReceipt {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client
                .join(opts, left_receipt, right_receipt, receipt_out)
        })
    }

    fn identity_p254(&self, opts: ProverOpts, receipt: Asset) -> SuccinctReceipt {
        with_server(self.addr, || {
            let receipt_out = AssetRequest::Path(self.get_work_path());
            self.client.identity_p254(opts, receipt, receipt_out)
        })
    }
}

fn with_server<T, F: FnOnce() -> Result<T>>(addr: SocketAddr, f: F) -> T {
    let addr = addr.to_string();
    let handle = thread::Builder::new()
        .name("server".into())
        .spawn(move || {
            let server = ApiServer::new_tcp(addr);
            server.run().unwrap();
        })
        .unwrap();

    let result = f().unwrap();
    handle.join().unwrap();
    result
}

#[test]
fn execute() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());
    TestClient::new().execute(env, binary);
}

#[test]
fn prove() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Path(MULTI_TEST_PATH.into());
    let opts = ProverOpts::default();
    let receipt = TestClient::new().prove(env, opts, binary);
    receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]
fn prove_segment_elf() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::DoNothing)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());

    let mut client = TestClient::new();

    let session = client.execute(env, binary);
    assert_eq!(session.segments.len(), client.segments.len());

    let ctx = VerifierContext::default();
    for segment in client.segments.iter() {
        let opts = ProverOpts::default();
        let receipt = client.prove_segment(opts, segment.clone());
        receipt.verify_integrity_with_context(&ctx).unwrap();
    }
}

#[test]
fn lift_join_identity() {
    let segment_limit_po2 = 16; // 64k cycles
    let cycles = 1 << segment_limit_po2;
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::BusyLoop { cycles })
        .unwrap()
        .segment_limit_po2(segment_limit_po2)
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());

    let mut client = TestClient::new();

    let session = client.execute(env, binary);
    assert_eq!(session.segments.len(), client.segments.len());

    let opts = ProverOpts::default();

    let receipt = client.prove_segment(opts.clone(), client.segments[0].clone());
    let mut rollup = client.lift(opts.clone(), receipt.try_into().unwrap());

    for segment in &client.segments[1..] {
        let receipt = client.prove_segment(opts.clone(), segment.clone());
        let rec_receipt = client.lift(opts.clone(), receipt.try_into().unwrap());

        rollup = client.join(
            opts.clone(),
            rollup.try_into().unwrap(),
            rec_receipt.try_into().unwrap(),
        );
        rollup
            .verify_integrity_with_context(&VerifierContext::default())
            .unwrap();
    }
    client.identity_p254(opts, rollup.clone().try_into().unwrap());

    let rollup_receipt = Receipt::new(InnerReceipt::Succinct(rollup), session.journal.bytes.into());
    rollup_receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]
fn stark2snark() {
    const SEAL_FILE: &str = "seal.bin";

    let cycles = 0u32;
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::BusyLoop { cycles })
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());

    let mut client = TestClient::new();

    let session = client.execute(env, binary);
    assert_eq!(session.segments.len(), client.segments.len());

    let opts = ProverOpts::default();

    let receipt = client.prove_segment(opts.clone(), client.segments[0].clone());
    let mut rollup = client.lift(opts.clone(), receipt.try_into().unwrap());

    for segment in &client.segments[1..] {
        let receipt = client.prove_segment(opts.clone(), segment.clone());
        let rec_receipt = client.lift(opts.clone(), receipt.try_into().unwrap());

        rollup = client.join(
            opts.clone(),
            rollup.try_into().unwrap(),
            rec_receipt.try_into().unwrap(),
        );
        rollup
            .verify_integrity_with_context(&VerifierContext::default())
            .unwrap();
    }
    let receipt_ident = client.identity_p254(opts, rollup.clone().try_into().unwrap());

    let work_dir = tempdir().expect("Failed to create tmpdir");
    let seal_path = work_dir.path().join(SEAL_FILE);
    std::fs::write(&seal_path, &receipt_ident.get_seal_bytes())
        .expect("Failed to write seal-to-json stdout to disk");

    let journal = session.journal.bytes;

    let rollup_receipt = Receipt::new(InnerReceipt::Succinct(rollup), journal.clone());
    rollup_receipt.verify(MULTI_TEST_ID).unwrap();

    // let ceremony_path = Path::new("../..").join(CEREMONY_DIR);
    // if !ceremony_path.exists() {
    //     panic!("Missing ceremony path");
    // }

    // let seal_to_json_path = ceremony_path.join("seal-to-json");

    // println!("Running seal-to-json");
    // let mut child = Command::new(seal_to_json_path)
    //     .stdin(Stdio::piped())
    //     .stdout(Stdio::piped())
    //     .spawn()
    //     .unwrap();

    // if let Some(mut stdin) = child.stdin.take() {
    //     stdin.write_all(&receipt_ident.get_seal_bytes()).unwrap();
    // }

    // let output = child.wait_with_output().unwrap();
    // if !output.status.success() {
    //     panic!("Failed to run seal-to-json");
    // }

    // println!("Running verify");
    // let verify_bin = ceremony_path.join("verify_cpp").join("verify");
    // let witness_path = work_dir.path().join(WITNESS_FILE);
    // let child = Command::new(verify_bin)
    //     .arg(&seal_path)
    //     .arg(&witness_path)
    //     .spawn()
    //     .unwrap();

    // let res = child.wait_with_output().unwrap();
    // if !res.status.success() {
    //     panic!("Failed to run verify");
    // }

    // println!("Running rapidsnark");
    // let zkey_file = ceremony_path.join("verify_final.zkey");
    // let proof_file = work_dir.path().join(PROOF_FILE);
    // let public_file = work_dir.path().join(PUBLIC_FILE);

    // let child = Command::new("rapidsnark")
    //     .arg(zkey_file)
    //     .arg(witness_path)
    //     .arg(&proof_file)
    //     .arg(&public_file)
    //     .spawn()
    //     .unwrap();
    // let res = child.wait_with_output().unwrap();
    // if !res.status.success() {
    //     panic!("Failed to run rapidsnark");
    // }

    // let output = Command::new("snarkjs")
    //     .arg("zkey")
    //     .arg("export")
    //     .arg("soliditycalldata")
    //     .arg(&public_file)
    //     .arg(&proof_file)
    //     .output()
    //     .unwrap();
    // if !output.status.success() {
    //     panic!("Failed to run snarkjs");
    // }

    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(&format!(
            "{:}:/app/seal.bin:ro",
            seal_path.to_string_lossy()
        ))
        .arg("angelocapossele/risc0-groth16-prover:v0.0.1")
        .output()
        .unwrap();

    let snark_str = String::from_utf8(output.stdout).unwrap();
    let snark_str = format!("[{snark_str}]"); // make the output valid json
    println!("{snark_str}");

    let raw_proof: (Vec<String>, Vec<Vec<String>>, Vec<String>, Vec<String>) =
        serde_json::from_str(&snark_str).unwrap();
    let a: Result<Vec<Vec<u8>>, hex::FromHexError> = raw_proof
        .0
        .into_iter()
        .map(|elm| hex::decode(&elm[2..]))
        .collect();
    let a = a.expect("Failed to decode snark 'a' values");

    let b: Result<Vec<Vec<Vec<u8>>>, hex::FromHexError> = raw_proof
        .1
        .into_iter()
        .map(|inner| {
            inner
                .into_iter()
                .map(|elm| hex::decode(&elm[2..]))
                .collect::<Result<Vec<Vec<u8>>, hex::FromHexError>>()
        })
        .collect();
    let b = b.expect("Failed to decode snark 'b' values");

    let c: Result<Vec<Vec<u8>>, hex::FromHexError> = raw_proof
        .2
        .into_iter()
        .map(|elm| hex::decode(&elm[2..]))
        .collect();
    let c = c.expect("Failed to decode snark 'c' values");

    let groth16_seal = Groth16Seal { a, b, c };
    let receipt = Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt {
            seal: groth16_seal.to_vec(),
            claim: rollup_receipt.get_claim().unwrap(),
        }),
        journal,
    );

    receipt.verify(MULTI_TEST_ID).unwrap();
}

#[test]
#[should_panic(expected = "Guest panicked: panicked at 'MultiTestSpec::Panic invoked'")]
fn guest_error_forwarding() {
    let env = ExecutorEnv::builder()
        .write(&MultiTestSpec::Panic)
        .unwrap()
        .build()
        .unwrap();
    let binary = Asset::Inline(MULTI_TEST_ELF.into());
    TestClient::new().execute(env, binary);
}
