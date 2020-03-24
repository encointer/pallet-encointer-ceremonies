//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! # Encointer Ceremonies Module
//!
//! The Encointer Ceremonies module provides functionality for
//! - registering for upcoming ceremony
//! - meetup assignment
//! - attestation registry
//! - issuance of basic income
//!

#![cfg_attr(not(feature = "std"), no_std)]

use support::{
    decl_event, decl_module, decl_storage,
    dispatch::Result,
    ensure,
    storage::{StorageDoubleMap, StorageMap},
};
use system::ensure_signed;

use rstd::cmp::min;
use rstd::prelude::*;

use runtime_io::misc::print_utf8;
use sr_primitives::traits::{IdentifyAccount, Member, Verify};

use codec::{Decode, Encode};

use encointer_currencies::{CurrencyIdentifier, Location};
use encointer_balances::traits::MultiCurrency;
use encointer_scheduler::{CeremonyIndexType, CeremonyPhaseType, OnCeremonyPhaseChange};

pub trait Trait: system::Trait 
    + encointer_currencies::Trait 
    + encointer_balances::Trait 
    + encointer_scheduler::Trait
{
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = Self::Public> + Member + Decode + Encode;
}

const REPUTATION_LIFETIME: u32 = 1;

pub type ParticipantIndexType = u64;
pub type MeetupIndexType = u64;
pub type AttestationIndexType = u64;
pub type CurrencyCeremony = (CurrencyIdentifier, CeremonyIndexType);

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Debug)]
pub enum Reputation {
    // no attestations for attendance claim
    Unverified,
    // no attestation yet but linked to reputation
    UnverifiedReputable,
    // verified former attendance that has not yet been linked to a new registration
    VerifiedUnlinked,
    // verified former attendance that has already been linked to a new registration
    VerifiedLinked,
}
impl Default for Reputation {
    fn default() -> Self {
        Reputation::Unverified
    }
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Attestation<Signature, AccountId> {
    pub claim: ClaimOfAttendance<AccountId>,
    pub signature: Signature,
    pub public: AccountId,
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ClaimOfAttendance<AccountId> {
    pub claimant_public: AccountId,
    pub ceremony_index: CeremonyIndexType,
    pub currency_identifier: CurrencyIdentifier,
    pub meetup_index: MeetupIndexType,
    pub location: Location,
    pub number_of_participants_confirmed: u32,
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ProofOfAttendance<Signature, AccountId> {
    pub prover_public: AccountId,
    pub ceremony_index: CeremonyIndexType,
    pub currency_identifier: CurrencyIdentifier,
    pub attendee_public: AccountId,
    pub attendee_signature: Signature,
}

// This module's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as EncointerCeremonies {
        // everyone who registered for a ceremony
        // caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
        ParticipantRegistry get(participant_registry): double_map CurrencyCeremony, blake2_256(ParticipantIndexType) => T::AccountId;
        ParticipantIndex get(participant_index): double_map CurrencyCeremony, blake2_256(T::AccountId) => ParticipantIndexType;
        ParticipantCount get(participant_count): map CurrencyCeremony => ParticipantIndexType;
        ParticipantReputation get(participant_reputation): double_map CurrencyCeremony, blake2_256(T::AccountId) => Reputation;

        // all meetups for each ceremony mapping to a vec of participants
        // caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
        MeetupRegistry get(meetup_registry): double_map CurrencyCeremony, blake2_256(MeetupIndexType) => Vec<T::AccountId>;
        MeetupIndex get(meetup_index): double_map CurrencyCeremony, blake2_256(T::AccountId) => MeetupIndexType;
        MeetupCount get(meetup_count): map CurrencyCeremony => MeetupIndexType;

        // collect fellow meetup participants accounts who attestationed key account
        // caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
        AttestationRegistry get(attestation_registry): double_map CurrencyCeremony, blake2_256(AttestationIndexType) => Vec<T::AccountId>;
        AttestationIndex get(attestation_index): double_map CurrencyCeremony, blake2_256(T::AccountId) => AttestationIndexType;
        AttestationCount get(attestation_count): map CurrencyCeremony => AttestationIndexType;
        // how many peers does each participants observe at their meetup
        MeetupParticipantCountVote get(meetup_participant_count_vote): double_map CurrencyCeremony, blake2_256(T::AccountId) => u32;
        CeremonyReward get(ceremony_reward) config(): T::Balance;
        // [m] distance from assigned meetup location
        LocationTolerance get(location_tolerance) config(): u32; 
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        pub fn grant_reputation(origin, cid: CurrencyIdentifier, reputable: T::AccountId) -> Result {
            let sender = ensure_signed(origin)?;
            ensure!(sender == <encointer_scheduler::Module<T>>::ceremony_master(), "only the CeremonyMaster can call this function");
            let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index();
            <ParticipantReputation<T>>::insert(&(cid, cindex-1), reputable, Reputation::VerifiedUnlinked);
            Ok(())
        }

        pub fn register_participant(origin, cid: CurrencyIdentifier, proof: Option<ProofOfAttendance<T::Signature, T::AccountId>>) -> Result {
            let sender = ensure_signed(origin)?;
            ensure!(<encointer_scheduler::Module<T>>::current_phase() == CeremonyPhaseType::REGISTERING,
                "registering participants can only be done during REGISTERING phase");

            ensure!(<encointer_currencies::Module<T>>::currency_identifiers().contains(&cid),
                "CurrencyIdentifier not found");

            let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index();

            if <ParticipantIndex<T>>::exists((cid, cindex), &sender) {
                return Err("already registered participant")
            }

            let count = <ParticipantCount>::get((cid, cindex));

            let new_count = count.checked_add(1).
                ok_or("[EncointerCeremonies]: Overflow adding new participant to registry")?;
            if let Some(p) = proof {
                // we accept proofs from other currencies as well. no need to ensure cid
                ensure!(sender == p.prover_public, "supplied proof is not proving sender");
                ensure!(p.ceremony_index < cindex, "proof is acausal");
                ensure!(p.ceremony_index >= cindex-REPUTATION_LIFETIME, "proof is outdated");
                ensure!(Self::participant_reputation(&(p.currency_identifier, p.ceremony_index),
                    &p.attendee_public) == Reputation::VerifiedUnlinked,
                    "former attendance has not been verified or has already been linked to other account");
                if Self::verify_attendee_signature(p.clone()).is_err() {
                    return Err("proof of attendance has bad signature");
                };

                // this reputation must now be burned so it can not be used again
                <ParticipantReputation<T>>::insert(&(p.currency_identifier, p.ceremony_index),
                    &p.attendee_public, Reputation::VerifiedLinked);
                // register participant as reputable
                <ParticipantReputation<T>>::insert((cid, cindex),
                    &sender, Reputation::UnverifiedReputable);
            };
            <ParticipantRegistry<T>>::insert((cid, cindex), &new_count, &sender);
            <ParticipantIndex<T>>::insert((cid, cindex), &sender, &new_count);
            <ParticipantCount>::insert((cid, cindex), new_count);
            Ok(())
        }

        pub fn register_attestations(origin, attestations: Vec<Attestation<T::Signature, T::AccountId>>) -> Result {
            let sender = ensure_signed(origin)?;
            ensure!(<encointer_scheduler::Module<T>>::current_phase() == CeremonyPhaseType::ATTESTING,
                "registering attestations can only be done during ATTESTING phase");
            let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index();
            ensure!(attestations.len()>0, "empty attestations supplied");
            let cid = attestations[0].claim.currency_identifier;
            ensure!(<encointer_currencies::Module<T>>::currency_identifiers().contains(&cid),
                "CurrencyIdentifier not found");

            let meetup_index = Self::meetup_index((cid, cindex), &sender);
            let mut meetup_participants = Self::meetup_registry((cid, cindex), &meetup_index);
            ensure!(meetup_participants.contains(&sender), "origin not part of this meetup");
            meetup_participants.retain(|x| x != &sender);
            let num_registered = meetup_participants.len();
            let num_signed = attestations.len();
            ensure!(num_signed <= num_registered, "can\'t have more attestations than other meetup participants");
            let mut verified_attestation_accounts = vec!();
            let mut claim_n_participants = 0u32;

            // FIXME: this could panic due to index out of bounds!
            let mlocation = <encointer_currencies::Module<T>>::locations(&cid)[(meetup_index-1) as usize];

            for w in 0..num_signed {
                let attestation = &attestations[w];
                let attestation_account = &attestations[w].public;
                if meetup_participants.contains(attestation_account) == false {
                    print_utf8(b"ignoring attestation that isn't a meetup participant");
                    continue };
                if attestation.claim.ceremony_index != cindex {
                    print_utf8(b"ignoring claim with wrong ceremony index");
                    continue };
                if attestation.claim.currency_identifier != cid {
                    print_utf8(b"ignoring claim with wrong currency identifier");
                    continue };
                if attestation.claim.meetup_index != meetup_index {
                    print_utf8(b"ignoring claim with wrong meetup index");
                    continue };
                if !<encointer_currencies::Module<T>>::is_valid_geolocation(
                    &attestation.claim.location) {
                        return Err("illegal geolocation");
                        print_utf8(b"ignoring claim with illegal geolocation");
                        continue };   
                if <encointer_currencies::Module<T>>::haversine_distance(
                    &mlocation, &attestation.claim.location) > Self::location_tolerance() {
                        return Err("too far away");
                        print_utf8(b"ignoring claim beyond location tolerance");
                        continue };     
                if Self::verify_attestation_signature(attestation.clone()).is_err() {
                    print_utf8(b"ignoring attestation with bad signature");
                    continue };
                // attestation is legit. insert it!
                verified_attestation_accounts.insert(0, attestation_account.clone());
                // is it a problem if this number isn't equal for all claims? Guess not.
                claim_n_participants = attestation.claim.number_of_participants_confirmed;
            }
            if verified_attestation_accounts.len() == 0 {
                return Err("no valid attestations found");
            }

            let count = <AttestationCount>::get((cid, cindex));
            let mut idx = count+1;

            if <AttestationIndex<T>>::exists((cid, cindex), &sender) {
                idx = <AttestationIndex<T>>::get((cid, cindex), &sender);
            } else {
                let new_count = count.checked_add(1).
                    ok_or("[EncointerCeremonies]: Overflow adding new attestation to registry")?;
                <AttestationCount>::insert((cid, cindex), new_count);
            }
            <AttestationRegistry<T>>::insert((cid, cindex), &idx, &verified_attestation_accounts);
            <AttestationIndex<T>>::insert((cid, cindex), &sender, &idx);
            <MeetupParticipantCountVote<T>>::insert((cid, cindex), &sender, &claim_n_participants);
            Ok(())
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        ParticipantRegistered(AccountId),
    }
);

impl<T: Trait> Module<T> {

    fn purge_registry(cindex: CeremonyIndexType) -> Result {
        let cids = <encointer_currencies::Module<T>>::currency_identifiers();
        for cid in cids.iter() {
            <ParticipantRegistry<T>>::remove_prefix((cid, cindex));
            <ParticipantIndex<T>>::remove_prefix((cid, cindex));
            <ParticipantCount>::insert((cid, cindex), 0);
            <MeetupRegistry<T>>::remove_prefix((cid, cindex));
            <MeetupIndex<T>>::remove_prefix((cid, cindex));
            <MeetupCount>::insert((cid, cindex), 0);
            <AttestationRegistry<T>>::remove_prefix((cid, cindex));
            <AttestationIndex<T>>::remove_prefix((cid, cindex));
            <AttestationCount>::insert((cid, cindex), 0);
            <MeetupParticipantCountVote<T>>::remove_prefix((cid, cindex));
        }
        Ok(())
    }

    /* this is for a more recent revision of substrate....
    fn random_permutation(elements: Vec<u8>) -> Vec<u8> {
        let random_seed = <system::Module<T>>::random_seed();
        let out = Vec::with_capacity(elements.len());
        let n = elements.len();
        for i in 0..n {
            let new_random = (random_seed, i)
                .using_encoded(|b| Blake2Hasher::hash(b))
                .using_encoded(|mut b| u64::decode(&mut b))
                .expect("Hash must be bigger than 8 bytes; Qed");
            let elem = elements.remove(new_random % elements.len());
            out.push(elem);
        }
        out
    }
    */

    // this function is expensive, so it should later be processed off-chain within SubstraTEE-worker
    // currently the complexity is O(n) where n is the number of registered participants
    fn assign_meetups() -> Result {
        let cids = <encointer_currencies::Module<T>>::currency_identifiers();
        for cid in cids.iter() {
            let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index();
            let pcount = <ParticipantCount>::get((cid, cindex));

            let mut reputables = Vec::with_capacity(pcount as usize);
            let mut newbies = Vec::with_capacity(pcount as usize);

            // TODO: upfront random permutation
            for p in 1..=pcount {
                let participant = <ParticipantRegistry<T>>::get((cid, cindex), &p);
                if Self::participant_reputation((cid, cindex), &participant)
                    == Reputation::UnverifiedReputable
                    || <encointer_currencies::Module<T>>::bootstrappers(cid).contains(&participant)
                {
                    reputables.push(participant);
                } else {
                    newbies.push(participant);
                }
            }
            let mut n = reputables.len();
            n += min(newbies.len(), n / 4);
            let n_meetups = n / 12 + 1;
            let mut meetups = Vec::with_capacity(n_meetups);
            let mut meetup_n_rep = vec![0; n_meetups];
            for _i in 0..n_meetups {
                meetups.push(Vec::with_capacity(12))
            }
            // first, evenly assign reputables to meetups
            for (i, p) in reputables.iter().enumerate() {
                meetups[i % n_meetups].push(p);
                meetup_n_rep[i % n_meetups] += 1;
            }
            // now, distribute newbies, complying with newbie limit per meetup
            // FIXME: stop after skipping n_meetups newbies
            for (i, p) in newbies.iter().enumerate() {
                let _idx = i % n_meetups;
                if meetups[_idx].len() < meetup_n_rep[_idx] * 4 / 3 {
                    meetups[i % n_meetups].push(p);
                } else {
                    print_utf8(b"had to skip one newbie");
                }
            }
            // purge meetups that are too small
            let mut toosmall = Vec::with_capacity(n_meetups);
            for (i, m) in meetups.iter().enumerate() {
                if m.len() < 3 {
                    toosmall.push(i);
                    print_utf8(b"one meetup can't take place because it is too small");
                }
            }
            for i in toosmall {
                meetups.remove(i);
            }
            // FIXME: with nightly we could do: meetups.drain_filter(|x| x.len() < 3).collect::<Vec<_>>();

            if meetups.is_empty() {
                return Ok(());
            };

            // commit result to state
            <MeetupCount>::insert((cid, cindex), n_meetups as MeetupIndexType);
            for (i, m) in meetups.iter().enumerate() {
                let _idx = (i + 1) as MeetupIndexType;
                for p in meetups[i].iter() {
                    <MeetupIndex<T>>::insert((cid, cindex), p, &_idx);
                }
                <MeetupRegistry<T>>::insert((cid, cindex), &_idx, m.clone());
            }
        }
        Ok(())
    }

    fn verify_attestation_signature(
        attestation: Attestation<T::Signature, T::AccountId>,
    ) -> Result {
        ensure!(
            attestation.public != attestation.claim.claimant_public,
            "attestation may not be self-signed"
        );
        match attestation
            .signature
            .verify(&attestation.claim.encode()[..], &attestation.public)
        {
            true => Ok(()),
            false => Err("attestation signature is invalid"),
        }
    }

    fn verify_attendee_signature(proof: ProofOfAttendance<T::Signature, T::AccountId>) -> Result {
        match proof.attendee_signature.verify(
            &(proof.prover_public, proof.ceremony_index).encode()[..],
            &proof.attendee_public,
        ) {
            true => Ok(()),
            false => Err("attendee signature is invalid"),
        }
    }

    // this function takes O(n) for n meetups, so it should later be processed off-chain within
    // SubstraTEE-worker together with the entire registry
    // as this function can only be called by the ceremony state machine, it could actually work out fine
    // on-chain. It would just delay the next block once per ceremony cycle.
    fn issue_rewards() -> Result {
        let cids = <encointer_currencies::Module<T>>::currency_identifiers();
        for cid in cids.iter() {
            ensure!(
                <encointer_scheduler::Module<T>>::current_phase() == CeremonyPhaseType::REGISTERING,
                "issuance can only be called at the end of ATTESTING phase"
            );
            let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index() -1;
            let meetup_count = Self::meetup_count((cid, cindex));
            let reward = Self::ceremony_reward();

            for m in 1..=meetup_count {
                // first, evaluate votes on how many participants showed up
                let (n_confirmed, n_honest_participants) = match Self::ballot_meetup_n_votes(cid, cindex, m)
                {
                    Some(nn) => nn,
                    _ => {
                        print_utf8(b"skipping meetup because votes for num of participants are not dependable");
                        continue;
                    }
                };
                let meetup_participants = Self::meetup_registry((cid, cindex), &m);
                for p in meetup_participants {
                    if Self::meetup_participant_count_vote((cid, cindex), &p) != n_confirmed {
                        print_utf8(b"skipped participant because of wrong participant count vote");
                        continue;
                    }
                    let attestations = Self::attestation_registry(
                        (cid, cindex),
                        &Self::attestation_index((cid, cindex), &p),
                    );
                    if attestations.len() < (n_honest_participants - 1) as usize
                        || attestations.is_empty()
                    {
                        print_utf8(b"skipped participant because of too few attestations");
                        continue;
                    }
                    let mut has_attested = 0u32;
                    for w in attestations {
                        let w_attestations = Self::attestation_registry(
                            (cid, cindex),
                            &Self::attestation_index((cid, cindex), &w),
                        );
                        if w_attestations.contains(&p) {
                            has_attested += 1;
                        }
                    }
                    if has_attested < (n_honest_participants - 1) {
                        print_utf8(b"skipped participant because didn't testify for honest peers");
                        continue;
                    }
                    // TODO: check that p also signed others
                    // participant merits reward
                    print_utf8(b"participant merits reward");
                    match <encointer_balances::Module<T> as MultiCurrency<_>>::deposit(*cid, &p, reward) {
                        Ok(()) => (),
                        _ => return Err("could not issue reward")
                    };
                    <ParticipantReputation<T>>::insert(
                        (cid, cindex),
                        &p,
                        Reputation::VerifiedUnlinked,
                    );
                }
            }
        }
        Ok(())
    }

    fn ballot_meetup_n_votes(
        cid: &CurrencyIdentifier,
        cindex: CeremonyIndexType,
        meetup_idx: MeetupIndexType,
    ) -> Option<(u32, u32)> {
        let meetup_participants = Self::meetup_registry((cid, cindex), &meetup_idx);
        // first element is n, second the count of votes for n
        let mut n_vote_candidates: Vec<(u32, u32)> = vec![];
        for p in meetup_participants {
            let this_vote = match Self::meetup_participant_count_vote((cid, cindex), &p) {
                n if n > 0 => n,
                _ => continue,
            };
            match n_vote_candidates.iter().position(|&(n, _c)| n == this_vote) {
                Some(idx) => n_vote_candidates[idx].1 += 1,
                _ => n_vote_candidates.insert(0, (this_vote, 1)),
            };
        }
        if n_vote_candidates.is_empty() {
            return None;
        }
        // sort by descending vote count
        n_vote_candidates.sort_by(|a, b| b.1.cmp(&a.1));
        if n_vote_candidates[0].1 < 3 {
            return None;
        }
        Some(n_vote_candidates[0])
    }

    #[cfg(test)]
    // only to be used by tests
    fn fake_reputation(cidcindex: CurrencyCeremony, account: &T::AccountId, rep: Reputation) {
        <ParticipantReputation<T>>::insert(&cidcindex, account, rep);
    }
}

impl<T: Trait> OnCeremonyPhaseChange for Module<T> {
    fn on_ceremony_phase_change(new_phase: CeremonyPhaseType) 
    { 
        match new_phase {
            CeremonyPhaseType::ASSIGNING => {
                Self::assign_meetups();
            }
            CeremonyPhaseType::ATTESTING => { }
            CeremonyPhaseType::REGISTERING => { 
                Self::issue_rewards();
                let cindex = <encointer_scheduler::Module<T>>::current_ceremony_index();
                Self::purge_registry(cindex-1);
            }
        }
    }
}

#[cfg(test)]
mod tests;
