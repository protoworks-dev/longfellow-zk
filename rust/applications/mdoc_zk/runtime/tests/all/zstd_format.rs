// Copyright 2026 Google LLC.
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

//! The circuit archives are shipped zstd-compressed. The digests below are
//! those of the decompressed bytes of every checked-in archive, measured with
//! the zstd 0.13.3 crate before the move to 0.14; a decoder that reads the
//! same frames to the same bytes keeps them, and any difference fails here.

#[cfg(test)]
mod tests {
    use mdoc_zk_artifacts::{all_circuit_hashes, load_circuit_lfa1, load_circuit_lfa2};
    use sha2::{Digest, Sha256};

    /// (circuit hash, lfa1 length, lfa1 sha256, lfa2 length, lfa2 sha256)
    const DECOMPRESSED_UNDER_0_13: &[(&str, usize, &str, usize, &str)] = &[
        (
            "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
            87718862,
            "58504213811cfb3fcc4e8d2e37d4d67891977dac654dc31b3e17808cbf9c4066",
            1523581,
            "e74861c744d044e1ff65af4faebe602ff11e19e987721816ada5ef54ec4c35cb",
        ),
        (
            "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460",
            114608684,
            "5a282c3f77d35a32ec5af028ece8c2c8cab612f4aa1d178f7607984dd5787010",
            1898502,
            "0f33e8c8ea9d96cf2d02954c00e50b91dd30e2231eaf1dce97f5b53c9b19e168",
        ),
        (
            "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad",
            104158196,
            "894da3317a10fbfa745a4684040be9bf03e74bd0d69825afefc683fb6453a1a2",
            1738180,
            "f41985b2161891ab1afe33c819b6f392f1568249a26d5700b44ba6fdfff54bf5",
        ),
        (
            "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
            98932952,
            "332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835",
            1660470,
            "0dc4666fd4edcb7873db192825f12a0d15a71d97945ebc58934fbaae6f2cbfea",
        ),
        (
            "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f",
            109383440,
            "c2ec6b0b6947b8f78f543022ff1b6432b7bea7218546c185a299652f7571e01e",
            1849371,
            "1296f7a8bd2d69f439887878b73cfe445adb93cf7c73006773569838052496ae",
        ),
        (
            "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010",
            97592822,
            "761ff6f4c9e6549a5f96aafacc49c09904cd920f9ec6db794162df0405162d24",
            1674127,
            "fa891dd2843bc5ee81a174ea770922dede3c5a57d215e0189dd7efebb9363f3f",
        ),
        (
            "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
            92655842,
            "906d6b6be716d74c5f75154b72b921a8de2df05cea4d9e5eba60c2fe1f7d9304",
            1586657,
            "7e4733c2944d30f4e3f5da22a131f63b94290017c54d6722594dce2571d2d0e8",
        ),
        (
            "c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1",
            95835410,
            "b26c4932e07e08025df31497d4308217f51bc6ea589154c223c9a18c0238872c",
            1241998,
            "5666d16300ff02bda981a75bc8398b8ee9406efb64c1aacfe62d5433c5c9645c",
        ),
        (
            "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6",
            102529802,
            "a18a5598f1b3b9e2bfed31f345a66b33f641475c893dbc081fb2626f3a3809da",
            1720088,
            "117c13c26853a9627f1cb8c5b2a955350c9add0517f85f9e1a7c392a57e622b0",
        ),
        (
            "f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb",
            91007270,
            "d985ff1f89273efd08d5aadcc96a1d30c5efed685b96e2738135aa23c4a3acc6",
            1196551,
            "9c581fd7a9b3ba1d52ec70520216d424272348fb43fdbb96ba563af508c028a7",
        ),
        (
            "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f",
            86179130,
            "0129c88c5bdd0c6a290e0a08ce1fe298a093ce07119062e178a80dcf2377e72a",
            1146981,
            "64eeab64922b2d532e44ae922d5b702bfb6391b5b45e51716c0e1d02b5bd9f7d",
        ),
        (
            "fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a",
            100663550,
            "fb93b3477b110b7adf1f72f97f2af113065f125b66304745066172f80a93e6a2",
            1255196,
            "92b98d15aab004991524a9bfad76cb568517d55a7e161097fca376ebdd66be22",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn decode(compressed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        zstd::stream::copy_decode(std::io::Cursor::new(compressed), &mut out)
            .expect("the archive is a valid zstd frame");
        out
    }

    #[test]
    fn the_table_covers_every_checked_in_circuit() {
        let mut table: Vec<&str> = DECOMPRESSED_UNDER_0_13.iter().map(|r| r.0).collect();
        let mut all: Vec<&str> = all_circuit_hashes().to_vec();
        table.sort_unstable();
        all.sort_unstable();
        assert_eq!(table, all);
    }

    #[test]
    fn archives_compressed_under_0_13_decompress_to_the_same_bytes() {
        for (hash, len1, sha1, len2, sha2) in DECOMPRESSED_UNDER_0_13 {
            let raw1 = decode(&load_circuit_lfa1(hash));
            assert_eq!(raw1.len(), *len1, "lfa1 length of {hash}");
            assert_eq!(hex(&Sha256::digest(&raw1)), *sha1, "lfa1 digest of {hash}");
            let raw2 = decode(&load_circuit_lfa2(hash));
            assert_eq!(raw2.len(), *len2, "lfa2 length of {hash}");
            assert_eq!(hex(&Sha256::digest(&raw2)), *sha2, "lfa2 digest of {hash}");
        }
    }

    #[test]
    fn the_streaming_decoder_agrees_with_copy_decode() {
        use std::io::Read;
        let (hash, _, sha, _, _) = DECOMPRESSED_UNDER_0_13[0];
        let compressed = load_circuit_lfa1(hash);
        let mut decoder = zstd::stream::read::Decoder::new(&compressed[..]).expect("decoder");
        let mut streamed = Vec::new();
        decoder.read_to_end(&mut streamed).expect("stream decode");
        assert_eq!(hex(&Sha256::digest(&streamed)), sha);
    }

    #[test]
    fn what_this_version_compresses_decompresses_to_the_input() {
        let raw = decode(&load_circuit_lfa2(DECOMPRESSED_UNDER_0_13[0].0));
        for level in [1, 3, 19] {
            let compressed = zstd::encode_all(&raw[..], level).expect("encode_all");
            assert_eq!(decode(&compressed), raw, "encode_all at level {level}");
            let bulk = zstd::bulk::compress(&raw, level).expect("bulk compress");
            assert_eq!(decode(&bulk), raw, "bulk::compress at level {level}");
        }
    }
}
