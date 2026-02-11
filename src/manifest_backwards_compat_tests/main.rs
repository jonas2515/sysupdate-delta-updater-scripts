use serde::{Deserialize, Serialize};
use zvariant::{
    DeserializeDict, LE, SerializeDict, Type, as_value,
    serialized::Context,
    signature,
    signature::{Fields, Signature},
    to_bytes,
};

fn main() {
    let ctxt = Context::new_dbus(LE, 0);

    // First specify a v1 version of the format and make sure that deserializes
    // as expected.

    #[derive(Debug, PartialEq, Type, Eq, Serialize, Deserialize)]
    #[zvariant(signature = "a{sv}")]
    struct Manifest {
        #[serde(with = "as_value")]
        pub block_hashes: Vec<u64>,
    }

    let test_manifest_v1 = Manifest {
        block_hashes: [342, 39].to_vec(),
    };

    let encoded = to_bytes(ctxt, &test_manifest_v1).unwrap();
    let decoded: Manifest = encoded.deserialize().unwrap().0;
    assert_eq!(&decoded, &test_manifest_v1);

    // Now specify a potential v2 version of the format, and add an optional
    // new value to the vardict, while keeping the existing value as-is (this is
    // how we keep it backwards compatible).

    #[derive(Debug, PartialEq, Type, Eq, Serialize, Deserialize)]
    #[zvariant(signature = "a{sv}")]
    struct ManifestV2 {
        #[serde(with = "as_value::optional", skip_serializing_if = "Option::is_none")]
        pub block_hashes_v2: Option<Vec<i16>>,
        #[serde(with = "as_value")]
        pub block_hashes: Vec<u64>,
    }

    let test_manifest_v2 = ManifestV2 {
        block_hashes_v2: Some([0x24, 100, 3, 381, 391, 9].to_vec()),
        block_hashes: [0x186].to_vec(),
    };

    // Serialize, then deserialize to a Manifest v1 and assert that it
    // deserializes fine to that type.
    let encoded = to_bytes(ctxt, &test_manifest_v2).unwrap();
    let decoded: Manifest = encoded.deserialize().unwrap().0;
    assert_eq!(
        &decoded,
        &Manifest {
            block_hashes: [0x186].to_vec(),
        }
    );
}
