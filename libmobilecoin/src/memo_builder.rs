// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{common::*, keys::McAccountKey};
use core::convert::TryFrom;
use mc_account_keys::{AccountKey};
//use mc_account_keys::PublicAddress;
//use mc_crypto_keys::{ReprBytes, RistrettoPrivate, RistrettoPublic};
//use mc_fog_report_validation::FogResolver;
//use mc_transaction_core::{
    //get_tx_out_shared_secret, get_value_mask,
    //onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    //ring_signature::KeyImage,
    //tx::{TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    //Amount, BlockVersion, CompressedCommitment,
//};
//use mc_transaction_std::{InputCredentials, RTHMemoBuilder, TransactionBuilder};
use mc_transaction_std::{RTHMemoBuilder, SenderMemoCredential};
use mc_util_ffi::*;


/* ==== TxOutMemoBuilder ==== */

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
#[no_mangle]
pub extern "C" fn mc_memo_builder_sender_and_destination_create(
    account_key: FfiRefPtr<McAccountKey>,
) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let account_key = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&*account_key));
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Some(memo_builder_box)
    })
}

/// # Preconditions
///
/// * `account_key` - must be a valid `AccountKey` with `fog_info`.
#[no_mangle]
pub extern "C" fn mc_memo_builder_sender_payment_request_and_destination_create(
    payment_request_id: u64,
    account_key: FfiRefPtr<McAccountKey>,
) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let account_key = AccountKey::try_from_ffi(&account_key).expect("account_key is invalid");
        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&*account_key));
        rth_memo_builder.set_payment_request_id(payment_request_id);
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Some(memo_builder_box)
    })
}

#[no_mangle]
pub extern "C" fn mc_memo_builder_default_create(
    ) -> FfiOptOwnedPtr<McTxOutMemoBuilder> {
    ffi_boundary(|| {
        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> =
            Box::new(RTHMemoBuilder::default());
        Some(memo_builder_box)
    })
}
