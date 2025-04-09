mod uffi;
use uffi::issuer::Issuer;
use uffi::prover::Prover;
use uffi::types::{
    Credential, CredentialDefinition, CredentialDefinitionPrivate, CredentialKeyCorrectnessProof,
    CredentialOffer, CredentialRequest, CredentialRequestMetadata, CredentialRevocationState,
    Presentation, PresentationRequest, RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate, RevocationRegistryDelta, RevocationStatusList, Schema,
};
use uffi::verifier::Verifier;
use uffi::credential_conversions::CredentialConversions;

use anoncreds::w3c::credential_conversion::credential_to_w3c;
use anoncreds::w3c::prover::create_presentation;
use anoncreds::w3c::prover::process_credential;
use anoncreds::w3c::issuer::create_credential;
use anoncreds::w3c::verifier::verify_presentation;
use anoncreds::w3c::helpers;

use anoncreds::data_types::w3c;

uniffi::include_scaffolding!("anoncreds_uniffi");
