// Copyright 2026 Protoworks Group (Pty) Ltd.
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

//! The mdoc circuits ship as zstd frames under `mdoc_zk/artifacts`, and the
//! prover and the verifier read them through one function,
//! `mdoc_zk_runtime::decompress_circuits`. Every frame checked in there was
//! written before the zstd crate moved from 0.13 to 0.14, and these tests hold
//! the new crate to reading them exactly as before:
//!
//! - each frame decompresses to the bytes recorded in [`RECORDED`], by length and SHA-256, as
//!   measured with the reference `zstd` 1.5.7 decoder, the C library that both crate versions bind;
//! - through `decompress_circuits`, each frame yields the two circuits whose identifiers,
//!   recomputed from their content, hash to the name the file is stored under;
//! - a circuit compiled now and compressed the way the provider compresses it reads back to the
//!   archive it was compressed from, and to the circuits the current specification names.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use mdoc_zk_runtime::{decompress_circuits, provider, CURRENT_VERSION};
use runtime_algebra::{gf2_128::Gf2_128Field, p256::P256Field};
use sha2::{Digest, Sha256};

/// The magic number that opens every zstd frame (RFC 8878), as it lies on disk.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// One checked-in circuit pair: the name it is stored under, which is the
/// SHA-256 of its signature circuit's identifier followed by its hash
/// circuit's, and what its frames decompress to. The `.lfa1` frame and the
/// frame stored under the bare name hold the same LFA1 archive (the latter in
/// a frame whose header records the content size); the `.lfa2` frame holds
/// the LFA2 archive.
struct Recorded {
    name: &'static str,
    lfa1_len: usize,
    lfa1_sha256: &'static str,
    lfa2_len: usize,
    lfa2_sha256: &'static str,
}

const RECORDED: &[Recorded] = &[
    Recorded {
        name: "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
        lfa1_len: 87_718_862,
        lfa1_sha256: "58504213811cfb3fcc4e8d2e37d4d67891977dac654dc31b3e17808cbf9c4066",
        lfa2_len: 1_523_581,
        lfa2_sha256: "e74861c744d044e1ff65af4faebe602ff11e19e987721816ada5ef54ec4c35cb",
    },
    Recorded {
        name: "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460",
        lfa1_len: 114_608_684,
        lfa1_sha256: "5a282c3f77d35a32ec5af028ece8c2c8cab612f4aa1d178f7607984dd5787010",
        lfa2_len: 1_898_502,
        lfa2_sha256: "0f33e8c8ea9d96cf2d02954c00e50b91dd30e2231eaf1dce97f5b53c9b19e168",
    },
    Recorded {
        name: "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad",
        lfa1_len: 104_158_196,
        lfa1_sha256: "894da3317a10fbfa745a4684040be9bf03e74bd0d69825afefc683fb6453a1a2",
        lfa2_len: 1_738_180,
        lfa2_sha256: "f41985b2161891ab1afe33c819b6f392f1568249a26d5700b44ba6fdfff54bf5",
    },
    Recorded {
        name: "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
        lfa1_len: 98_932_952,
        lfa1_sha256: "332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835",
        lfa2_len: 1_660_470,
        lfa2_sha256: "0dc4666fd4edcb7873db192825f12a0d15a71d97945ebc58934fbaae6f2cbfea",
    },
    Recorded {
        name: "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f",
        lfa1_len: 109_383_440,
        lfa1_sha256: "c2ec6b0b6947b8f78f543022ff1b6432b7bea7218546c185a299652f7571e01e",
        lfa2_len: 1_849_371,
        lfa2_sha256: "1296f7a8bd2d69f439887878b73cfe445adb93cf7c73006773569838052496ae",
    },
    Recorded {
        name: "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010",
        lfa1_len: 97_592_822,
        lfa1_sha256: "761ff6f4c9e6549a5f96aafacc49c09904cd920f9ec6db794162df0405162d24",
        lfa2_len: 1_674_127,
        lfa2_sha256: "fa891dd2843bc5ee81a174ea770922dede3c5a57d215e0189dd7efebb9363f3f",
    },
    Recorded {
        name: "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
        lfa1_len: 92_655_842,
        lfa1_sha256: "906d6b6be716d74c5f75154b72b921a8de2df05cea4d9e5eba60c2fe1f7d9304",
        lfa2_len: 1_586_657,
        lfa2_sha256: "7e4733c2944d30f4e3f5da22a131f63b94290017c54d6722594dce2571d2d0e8",
    },
    Recorded {
        name: "c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1",
        lfa1_len: 95_835_410,
        lfa1_sha256: "b26c4932e07e08025df31497d4308217f51bc6ea589154c223c9a18c0238872c",
        lfa2_len: 1_241_998,
        lfa2_sha256: "5666d16300ff02bda981a75bc8398b8ee9406efb64c1aacfe62d5433c5c9645c",
    },
    Recorded {
        name: "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6",
        lfa1_len: 102_529_802,
        lfa1_sha256: "a18a5598f1b3b9e2bfed31f345a66b33f641475c893dbc081fb2626f3a3809da",
        lfa2_len: 1_720_088,
        lfa2_sha256: "117c13c26853a9627f1cb8c5b2a955350c9add0517f85f9e1a7c392a57e622b0",
    },
    Recorded {
        name: "f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb",
        lfa1_len: 91_007_270,
        lfa1_sha256: "d985ff1f89273efd08d5aadcc96a1d30c5efed685b96e2738135aa23c4a3acc6",
        lfa2_len: 1_196_551,
        lfa2_sha256: "9c581fd7a9b3ba1d52ec70520216d424272348fb43fdbb96ba563af508c028a7",
    },
    Recorded {
        name: "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f",
        lfa1_len: 86_179_130,
        lfa1_sha256: "0129c88c5bdd0c6a290e0a08ce1fe298a093ce07119062e178a80dcf2377e72a",
        lfa2_len: 1_146_981,
        lfa2_sha256: "64eeab64922b2d532e44ae922d5b702bfb6391b5b45e51716c0e1d02b5bd9f7d",
    },
    Recorded {
        name: "fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a",
        lfa1_len: 100_663_550,
        lfa1_sha256: "fb93b3477b110b7adf1f72f97f2af113065f125b66304745066172f80a93e6a2",
        lfa2_len: 1_255_196,
        lfa2_sha256: "92b98d15aab004991524a9bfad76cb568517d55a7e161097fca376ebdd66be22",
    },
];

/// One frame of a recorded circuit pair: its path under `circuits/`, and the
/// length and SHA-256 of what it decompresses to.
struct Frame {
    file: String,
    len: usize,
    sha256: &'static str,
}

fn frames(recorded: &Recorded) -> [Frame; 3] {
    [
        Frame {
            file: recorded.name.to_string(),
            len: recorded.lfa1_len,
            sha256: recorded.lfa1_sha256,
        },
        Frame {
            file: format!("{}.lfa1", recorded.name),
            len: recorded.lfa1_len,
            sha256: recorded.lfa1_sha256,
        },
        Frame {
            file: format!("{}.lfa2", recorded.name),
            len: recorded.lfa2_len,
            sha256: recorded.lfa2_sha256,
        },
    ]
}

fn artifacts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../artifacts")
}

fn read_circuit_file(file: &str) -> Vec<u8> {
    let path = artifacts_dir().join("circuits").join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Decompresses a frame with the decoder the runtime constructs over it.
fn decompress(compressed: &[u8]) -> Vec<u8> {
    let mut decoder =
        zstd::stream::read::Decoder::new(compressed).expect("a zstd decoder over the frame");
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("the frame decompresses");
    decompressed
}

/// Reads a compressed circuit pair the way the prover and the verifier do,
/// checks that each circuit's identifier is the one recomputed from its
/// content, and returns the name the pair is stored under: the SHA-256 of the
/// signature circuit's identifier followed by the hash circuit's.
fn read_back_name(p256: &P256Field, gf2: &Gf2_128Field, compressed: &[u8], what: &str) -> String {
    let (c_sig, c_hash) = decompress_circuits(compressed, p256, gf2)
        .unwrap_or_else(|e| panic!("{what}: decompress_circuits failed: {e}"));

    let sig_id = core_proto::circuit::compute_id(p256, &c_sig.raw);
    assert_eq!(sig_id, c_sig.id, "{what}: signature circuit identifier");
    let hash_id = core_proto::circuit::compute_id(gf2, &c_hash.raw);
    assert_eq!(hash_id, c_hash.id, "{what}: hash circuit identifier");

    let mut hasher = Sha256::new();
    hasher.update(sig_id);
    hasher.update(hash_id);
    hex(&hasher.finalize())
}

/// Collects the path, relative to `root`, of every file under `dir` that
/// starts with the zstd magic number.
fn collect_zstd_frames(root: &Path, dir: &Path, found: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            collect_zstd_frames(root, &path, found);
            continue;
        }
        let mut magic = [0u8; 4];
        let read = std::fs::File::open(&path).and_then(|mut file| file.read_exact(&mut magic));
        if read.is_ok() && magic == ZSTD_MAGIC {
            let relative = path
                .strip_prefix(root)
                .expect("a path under the artifacts directory");
            found.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

#[test]
fn test_every_checked_in_zstd_frame_is_recorded() {
    let mut recorded_names: Vec<&str> = RECORDED.iter().map(|r| r.name).collect();
    let mut listed_names: Vec<&str> = mdoc_zk_artifacts::all_circuit_hashes().to_vec();
    recorded_names.sort_unstable();
    listed_names.sort_unstable();
    assert_eq!(
        recorded_names, listed_names,
        "the table records every circuit the artifacts crate lists"
    );

    let mut expected: Vec<String> = RECORDED
        .iter()
        .flat_map(frames)
        .map(|frame| format!("circuits/{}", frame.file))
        .collect();
    expected.sort_unstable();

    let root = artifacts_dir();
    let mut found = Vec::new();
    collect_zstd_frames(&root, &root, &mut found);
    found.sort_unstable();

    assert_eq!(
        found, expected,
        "every zstd frame under mdoc_zk/artifacts, and nothing else, is recorded"
    );
}

#[test]
fn test_checked_in_frames_decompress_to_their_recorded_bytes() {
    for recorded in RECORDED {
        for frame in frames(recorded) {
            let decompressed = decompress(&read_circuit_file(&frame.file));
            assert_eq!(
                decompressed.len(),
                frame.len,
                "{}: decompressed length",
                frame.file
            );
            assert_eq!(
                hex(&Sha256::digest(&decompressed)),
                frame.sha256,
                "{}: SHA-256 of the decompressed bytes",
                frame.file
            );
        }
    }
}

#[test]
fn test_checked_in_frames_read_back_to_the_circuits_they_name() {
    let p256 = P256Field::new();
    let gf2 = Gf2_128Field::new();
    for recorded in RECORDED {
        for frame in frames(recorded) {
            let compressed = read_circuit_file(&frame.file);
            assert_eq!(
                read_back_name(&p256, &gf2, &compressed, &frame.file),
                recorded.name,
                "{}: the circuits it decompresses to are the ones its name hashes",
                frame.file
            );
        }
    }
}

#[test]
fn test_circuit_compiled_now_round_trips_through_zstd() {
    let p256 = P256Field::new();
    let gf2 = Gf2_128Field::new();

    let provided = provider::materialize(CURRENT_VERSION, 1).expect("the current circuits compile");
    assert!(
        provided.compressed.starts_with(&ZSTD_MAGIC),
        "the provider hands out a zstd frame"
    );

    let archive =
        core_proto::archive::CircuitArchive::from_bytes(&decompress(&provided.compressed))
            .expect("the frame holds a circuit archive");
    assert_eq!(
        archive, provided.archive,
        "the frame decompresses to the archive it was compressed from"
    );

    assert_eq!(
        read_back_name(&p256, &gf2, &provided.compressed, &provided.name),
        provided.spec.combined_hash_hex(),
        "the circuits read back are the ones the current specification names"
    );
}
