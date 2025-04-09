use super::error::ErrorCode;
use super::types::{
    Credential, CredentialDefinition, CredentialOffer, CredentialRequest,
    CredentialRequestMetadata, CredentialRequestTuple, CredentialRevocationState, Presentation,
    PresentationRequest, RequestedCredential, RevocationRegistryDefinition,
    RevocationRegistryDelta, RevocationStatusList, Schema, W3CCredential
};

use anoncreds::data_types::{cred_def::CredentialDefinitionId, schema::SchemaId};
use anoncreds::prover::{
    create_credential_request, create_or_update_revocation_state, create_presentation,
};
use anoncreds::tails::TailsFileReader;
use anoncreds::types::{
    CredentialRevocationState as RustCredentialRevocationState, LinkSecret, PresentCredentials,
};
use anoncreds::Error;
use anoncreds_clsignatures::{RevocationRegistry, Witness};
use std::collections::HashMap;
use std::sync::Arc;


pub struct W3cProver {}

impl W3cProver {
    pub fn new() -> Self {
        Self {}
    }
}

#[uniffi::export]
impl W3cProver {
    pub fn process_credential(
        &self,
        cred: Arc<W3CCredential>,
        cred_req_metadata: Arc<CredentialRequestMetadata>,
        link_secret: String,
        cred_def: Arc<CredentialDefinition>,
        rev_reg_def: Option<Arc<RevocationRegistryDefinition>>,
    ) -> Result<Arc<W3CCredential>, ErrorCode> {

        let link_secret =
            LinkSecret::try_from(link_secret.as_str()).map_err(|err| Error::from(err))?;
        let rev_reg_def = rev_reg_def.as_ref().map(|def| &def.0);
        let mut new_cred = cred.0.clone(); //.try_clone().map_err(|err| Error::from(err))?;
        
        anoncreds::w3c::prover::process_credential(
            &mut new_cred,
            &cred_req_metadata.0,
            &link_secret,
            &cred_def.0,
            rev_reg_def,
        )?;

        Ok(Arc::new(W3CCredential(new_cred)))
    
    }
}