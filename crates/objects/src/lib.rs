//! Encrypted objects (T-5, T-32 (6), OP-6, OP-7 (3)): voice, screenshots, adapters, personal models, base model files and export packages go to an S3-compatible store as ciphertext sealed under their own record key; an object is written once under `one/<owner>/<object id>` and never overwritten, and this crate has no delete, so erasure is the shred of that key.

use std::sync::Arc;

use object_store::aws::AmazonS3Builder;
use object_store::path::Path;
use object_store::{GetOptions, ObjectStore, PutMode, PutOptions, PutPayload};
use one_proto::ObjectId;

/// The prefix every object of an owner lives under, as listed in `conformance/store/erasure-scope.toml`.
pub const PREFIX: &str = "one";

/// Longest owner identifier, the `CHECK` of `one.account.owner`.
const OWNER_MAX_LEN: usize = 200;

/// Why an object operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ObjectsError {
    /// The store refused or could not be reached.
    #[error("object store: {0}")]
    Store(#[from] object_store::Error),
    /// An object with this id exists; objects are never overwritten.
    #[error("object already exists")]
    Exists,
    /// No such object.
    #[error("object not found")]
    Missing,
    /// An owner identifier is not a valid scope.
    #[error("invalid owner identifier")]
    Owner,
}

/// Where the store is and how to sign in; the secret comes from the process secret store (T-51).
pub struct Settings<'a> {
    /// S3 endpoint URL.
    pub endpoint: &'a str,
    /// Bucket in the user's region (OP-13).
    pub bucket: &'a str,
    /// Region name.
    pub region: &'a str,
    /// Access key id.
    pub access_key: &'a str,
    /// Secret access key.
    pub secret_key: &'a str,
    /// Plain HTTP, for the local store only.
    pub allow_http: bool,
}

/// An object store handle.
#[derive(Clone)]
pub struct Objects {
    store: Arc<dyn ObjectStore>,
}

fn path(owner: &str, id: ObjectId) -> Result<Path, ObjectsError> {
    let ok = !owner.is_empty()
        && owner.len() <= OWNER_MAX_LEN
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'));
    if !ok {
        return Err(ObjectsError::Owner);
    }
    Ok(Path::from_iter([PREFIX, owner, &id.to_string()]))
}

impl Objects {
    /// Connects to an S3-compatible store.
    ///
    /// # Errors
    /// [`ObjectsError::Store`] for invalid settings.
    pub fn s3(settings: &Settings<'_>) -> Result<Self, ObjectsError> {
        let store = AmazonS3Builder::new()
            .with_endpoint(settings.endpoint)
            .with_bucket_name(settings.bucket)
            .with_region(settings.region)
            .with_access_key_id(settings.access_key)
            .with_secret_access_key(settings.secret_key)
            .with_allow_http(settings.allow_http)
            .with_virtual_hosted_style_request(false)
            .build()?;
        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Writes `ciphertext` as object `id` of `owner`.
    ///
    /// # Errors
    /// [`ObjectsError::Exists`] when the id is taken, [`ObjectsError::Owner`], [`ObjectsError::Store`].
    pub async fn put(
        &self,
        owner: &str,
        id: ObjectId,
        ciphertext: Vec<u8>,
    ) -> Result<(), ObjectsError> {
        let options = PutOptions {
            mode: PutMode::Create,
            ..PutOptions::default()
        };
        match self
            .store
            .put_opts(&path(owner, id)?, PutPayload::from(ciphertext), options)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => Err(ObjectsError::Exists),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads object `id` of `owner`.
    ///
    /// # Errors
    /// [`ObjectsError::Missing`], [`ObjectsError::Owner`], [`ObjectsError::Store`].
    pub async fn get(&self, owner: &str, id: ObjectId) -> Result<Vec<u8>, ObjectsError> {
        let found = match self
            .store
            .get_opts(&path(owner, id)?, GetOptions::default())
            .await
        {
            Ok(found) => found,
            Err(object_store::Error::NotFound { .. }) => return Err(ObjectsError::Missing),
            Err(e) => return Err(e.into()),
        };
        Ok(found.bytes().await?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use one_proto::id::uuid_v7;

    use super::*;

    #[test]
    fn t_5_objects_live_under_the_owner_prefix() {
        let id = ObjectId::from_bytes(uuid_v7(1, [1; 10])).unwrap();
        let p = path("party:a", id).unwrap();
        assert_eq!(p.as_ref(), format!("one/party:a/{id}"));
        assert!(matches!(path("a/b", id), Err(ObjectsError::Owner)));
        assert!(matches!(path("", id), Err(ObjectsError::Owner)));
    }
}
