-------------------------- MODULE BootstrapTime --------------------------
EXTENDS Naturals, Integers, TLC

(*
 Independent FINITE symbolic composition of (1) signed-commitment bootstrap
 and (2) delayed TESLA message admission. Not Python refinement or a proof
 of Ed25519/HMAC. Ideal signatures accept only real signer, and distinct fresh
 challenges reject saved replies, UNLESS the chosen negative control disables
 one of those checks. ClockMode="legacy" models a receiver that resets to 1
 and then remains stale despite the sender clock advancing. "live" uses the
 trusted receiver clock on setup and every packet. S <= R + Bound is assumed
 by safe configs (Lag <= Bound); an unsafe margin is tested separately.
 Network delivery and setup relay are scheduled adversarially without fairness.
*)

CONSTANTS Delay, Lag, Bound, ClockMode, SigMode, NonceMode
ASSUME /\ Delay \in {1, 2}
       /\ Lag \in {0, 1}
       /\ Bound \in {0, 1}
       /\ ClockMode \in {"live", "legacy"}
       /\ SigMode \in {"check", "bypass"}
       /\ NonceMode \in {"check", "bypass"}

MaxTime == 2 + Delay
Times == 1..MaxTime
Kinds == {"none", "genuine", "attacker", "old-replay"}

VARIABLES senderNow, receiverNow, signed, installed, installedKind,
          actualInstalledAt, honestSent, honestBuffered, honestAccepted,
          forgedAccepted

vars == <<senderNow, receiverNow, signed, installed, installedKind,
          actualInstalledAt, honestSent, honestBuffered, honestAccepted,
          forgedAccepted>>

EffectiveNow == IF ClockMode = "live" THEN receiverNow ELSE 1
SetupGate == ClockMode = "legacy" \/ receiverNow + Bound < 1 + Delay
PacketGate == EffectiveNow + Bound < 1 + Delay

Init == /\ senderNow = 1
        /\ receiverNow = 1
        /\ signed = FALSE
        /\ installed = FALSE
        /\ installedKind = "none"
        /\ actualInstalledAt = 0
        /\ honestSent = FALSE
        /\ honestBuffered = FALSE
        /\ honestAccepted = FALSE
        /\ forgedAccepted = FALSE

Tick == /\ senderNow < MaxTime
        /\ senderNow' = senderNow + 1
        /\ receiverNow' \in {r \in Times :
              /\ receiverNow <= r
              /\ r <= senderNow + 1
              /\ senderNow + 1 - r <= Lag}
        /\ UNCHANGED <<signed, installed, installedKind, actualInstalledAt,
                        honestSent, honestBuffered, honestAccepted, forgedAccepted>>

CatchUp == /\ receiverNow < senderNow
           /\ receiverNow' = receiverNow + 1
           /\ UNCHANGED <<senderNow, signed, installed, installedKind,
                          actualInstalledAt, honestSent, honestBuffered,
                          honestAccepted, forgedAccepted>>

SignHonest == /\ ~signed
              /\ senderNow = 1
              /\ signed' = TRUE
              /\ UNCHANGED <<senderNow, receiverNow, installed, installedKind,
                             actualInstalledAt, honestSent, honestBuffered,
                             honestAccepted, forgedAccepted>>

(* Model verification as a cryptographic axiom: the 'check' mode does not
   permit installing an attacker-owned commitment. *)
InstallValid == /\ signed /\ ~installed /\ SetupGate
                /\ installed' = TRUE
                /\ installedKind' = "genuine"
                /\ actualInstalledAt' = receiverNow
                /\ UNCHANGED <<senderNow, receiverNow, signed,
                               honestSent, honestBuffered,
                               honestAccepted, forgedAccepted>>

(* Deliberately broken signature verification, for counterexample control. *)
InstallAttacker == /\ signed /\ ~installed /\ SigMode = "bypass"
                   /\ SetupGate
                   /\ installed' = TRUE
                   /\ installedKind' = "attacker"
                   /\ actualInstalledAt' = receiverNow
                   /\ UNCHANGED <<senderNow, receiverNow, signed,
                                  honestSent, honestBuffered,
                                  honestAccepted, forgedAccepted>>

(* Deliberately broken receiver challenge verification. *)
InstallOldReplay == /\ signed /\ ~installed /\ NonceMode = "bypass"
                    /\ SetupGate
                    /\ installed' = TRUE
                    /\ installedKind' = "old-replay"
                    /\ actualInstalledAt' = receiverNow
                    /\ UNCHANGED <<senderNow, receiverNow, signed,
                                   honestSent, honestBuffered,
                                   honestAccepted, forgedAccepted>>

SendHonest == /\ ~honestSent /\ senderNow = 1
              /\ honestSent' = TRUE
              /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                             installedKind, actualInstalledAt, honestBuffered,
                             honestAccepted, forgedAccepted>>

BufferHonest == /\ installed /\ installedKind = "genuine"
                /\ honestSent /\ ~honestBuffered /\ PacketGate
                /\ honestBuffered' = TRUE
                /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                               installedKind, actualInstalledAt, honestSent,
                               honestAccepted, forgedAccepted>>

AuthenticateHonest == /\ honestBuffered /\ ~honestAccepted
                      /\ senderNow >= 1 + Delay
                      /\ receiverNow >= 1 + Delay
                      /\ honestAccepted' = TRUE
                      /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                                     installedKind, actualInstalledAt,
                                     honestSent, honestBuffered, forgedAccepted>>

(* The adversary knows K1 as soon as its disclosure time passes, even if
   the receiver has not yet seen the network disclosure. *)
AcceptForgedAfterRelease == /\ installed /\ installedKind = "genuine"
                            /\ ~forgedAccepted
                            /\ senderNow >= 1 + Delay
                            /\ PacketGate
                            /\ forgedAccepted' = TRUE
                            /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                                           installedKind, actualInstalledAt,
                                           honestSent, honestBuffered, honestAccepted>>

Next == Tick \/ CatchUp \/ SignHonest
        \/ InstallValid \/ InstallAttacker \/ InstallOldReplay
        \/ SendHonest \/ BufferHonest \/ AuthenticateHonest
        \/ AcceptForgedAfterRelease

Spec == Init /\ [][Next]_vars

TypeOK == /\ senderNow \in Times
          /\ receiverNow \in Times
          /\ receiverNow <= senderNow
          /\ senderNow - receiverNow <= Lag
          /\ signed \in BOOLEAN
          /\ installed \in BOOLEAN
          /\ installedKind \in Kinds
          /\ actualInstalledAt \in {0} \cup Times
          /\ honestSent \in BOOLEAN
          /\ honestBuffered \in BOOLEAN
          /\ honestAccepted \in BOOLEAN
          /\ forgedAccepted \in BOOLEAN
          /\ installed = (installedKind # "none")
          /\ honestBuffered => honestSent
          /\ honestAccepted => honestBuffered

AuthenticatedAnchor == installedKind # "attacker"
ChallengeFreshness == installedKind # "old-replay"
NoReleasedForgery == ~forgedAccepted
HonestAfterDisclosure == honestAccepted => senderNow >= 1 + Delay
LiveSetupBeforeDisclosure == (ClockMode = "live" /\ installed) =>
    actualInstalledAt + Bound < 1 + Delay

(* Deliberately false liveness-style witness: a real message can authenticate. *)
NoHonestAuthentication == ~honestAccepted

=============================================================================
