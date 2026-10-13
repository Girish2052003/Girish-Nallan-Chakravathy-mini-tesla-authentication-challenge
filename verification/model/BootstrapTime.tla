\* This independent model covers one signed setup, one message interval, and
\* one message-authentication key. It uses finite symbolic states, not real Python,
\* signatures, or HMAC bytes. A state is a complete choice of all variable values.
\* TLC explores the allowed steps; it does not execute this file top to bottom.
\* A backslash followed by * begins a line comment. (* ... *) encloses a block
\* comment. Comments explain the model without affecting its possible states.
\* MODULE names this model and matches the BootstrapTime.tla filename.
-------------------------- MODULE BootstrapTime --------------------------
\* Load standard natural-number, integer, and TLC helper definitions.
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

\* Constants come from .cfg files and remain fixed for one run. Delay is the key
\* release wait; Lag bounds how far receiver time may trail sender time; Bound is
\* the safety margin used by the receiver. ClockMode chooses a live or stale clock.
\* SigMode and NonceMode choose real checks or intentionally broken controls.
\* A nonce here is the fresh challenge tying a setup reply to this receiver request.
CONSTANTS Delay, Lag, Bound, ClockMode, SigMode, NonceMode
\* ASSUME restricts valid configurations. /\ means AND and \in means belongs
\* to a set. Try only delays 1 or 2, keeping exploration finite.
ASSUME /\ Delay \in {1, 2}
       \* Actual receiver lag can be at most zero or one time interval in this model.
       /\ Lag \in {0, 1}
       \* The receiver's assumed sender-ahead margin can be zero or one. This allows
       \* unsafe Bound < Lag cases deliberately; the model does not assume safety for every config.
       /\ Bound \in {0, 1}
       \* The clock mode must be one of these exact text values: live or legacy.
       /\ ClockMode \in {"live", "legacy"}
       \* Signature verification is either enforced by the symbolic model or intentionally bypassed.
       /\ SigMode \in {"check", "bypass"}
       \* The fresh challenge check is likewise either enforced or intentionally bypassed.
       /\ NonceMode \in {"check", "bypass"}

\* == defines an expression. Stop the finite clock at one step after key 1
\* becomes public (1 + Delay); this includes a post-release attack opportunity.
MaxTime == 2 + Delay
\* 1..MaxTime is the inclusive set of allowed time values, starting at interval 1.
Times == 1..MaxTime
\* Braces form a set of setup-kind labels: no setup, genuine setup, attacker-owned
\* anchor, or replayed old setup. An anchor is the trusted public endpoint of a key chain.
Kinds == {"none", "genuine", "attacker", "old-replay"}

\* VARIABLES change between states. Keep sender/receiver clocks, whether a
\* fresh genuine setup was signed, and whether/what kind of setup was installed.
VARIABLES senderNow, receiverNow, signed, installed, installedKind,
          \* Also keep actual receiver time at installation and flags for honest message
          \* sending, buffering (temporary storage), and successful authentication.
          actualInstalledAt, honestSent, honestBuffered, honestAccepted,
          \* The final flag records whether a forged message was accepted after its key became public.
          forgedAccepted

\* <<...>> creates an ordered tuple. vars groups the clocks and setup state
\* so the temporal specification can describe a step that changes nothing.
vars == <<senderNow, receiverNow, signed, installed, installedKind,
          \* Include the remembered installation time and honest-message progress in that state tuple.
          actualInstalledAt, honestSent, honestBuffered, honestAccepted,
          \* Include the forgery flag too, so vars covers every declared state variable.
          forgedAccepted>>

\* IF/THEN/ELSE selects the time used for packet admission: actual receiverNow
\* for live mode, or a permanently stale 1 for legacy mode. = compares values.
EffectiveNow == IF ClockMode = "live" THEN receiverNow ELSE 1
\* \/ means OR. Legacy mode allows setup regardless of time; live mode requires
\* receiver time plus its margin to be strictly before key 1 is public.
SetupGate == ClockMode = "legacy" \/ receiverNow + Bound < 1 + Delay
\* Packet admission uses the chosen effective time and the same strict deadline.
\* Equality is already unsafe: anyone with the released key can make a valid tag.
PacketGate == EffectiveNow + Bound < 1 + Delay

\* Init specifies the starting state; every AND clause below must hold at once.
\* Begin the sender at message/key interval 1.
Init == /\ senderNow = 1
        \* Start the trusted receiver clock at 1 as well.
        /\ receiverNow = 1
        \* FALSE means no genuine challenged setup reply has been signed yet.
        /\ signed = FALSE
        \* No receiver setup has been installed initially.
        /\ installed = FALSE
        \* Use the none label to agree with the not-installed flag.
        /\ installedKind = "none"
        \* Use zero as a placeholder installation time before any setup is installed.
        /\ actualInstalledAt = 0
        \* No honest message has been transmitted yet.
        /\ honestSent = FALSE
        \* No honest message is buffered awaiting disclosure.
        /\ honestBuffered = FALSE
        \* No honest message has been authenticated.
        /\ honestAccepted = FALSE
        \* No forged message has been accepted.
        /\ forgedAccepted = FALSE

\* Tick is a possible state transition, enabled only before the finite maximum time.
Tick == /\ senderNow < MaxTime
        \* A prime marks a next-state value: senderNow' is exactly one greater. All
        \* clauses constrain this same transition, rather than running in written order.
        /\ senderNow' = senderNow + 1
        \* Choose any next receiver time r from Times that satisfies all clauses below.
        \* TLC explores all such permitted clock choices.
        /\ receiverNow' \in {r \in Times :
              \* The receiver clock must never move backward.
              /\ receiverNow <= r
              \* It must not get ahead of the sender's new time.
              /\ r <= senderNow + 1
              \* Its lag behind the new sender time must not exceed Lag.
              /\ senderNow + 1 - r <= Lag}
        \* UNCHANGED keeps the signature/setup flags and remembered installation time fixed.
        /\ UNCHANGED <<signed, installed, installedKind, actualInstalledAt,
                        \* Time passing alone also leaves every message-progress and forgery flag unchanged.
                        honestSent, honestBuffered, honestAccepted, forgedAccepted>>

\* Allow a separate receiver catch-up step only while it trails the sender.
CatchUp == /\ receiverNow < senderNow
           \* Advance receiver time by one interval without advancing sender time.
           /\ receiverNow' = receiverNow + 1
           \* Keep sender time and setup status fixed during this catch-up step.
           /\ UNCHANGED <<senderNow, signed, installed, installedKind,
                          \* Keep installation time and message-send/buffer status fixed too.
                          actualInstalledAt, honestSent, honestBuffered,
                          \* Catching up alone cannot authenticate or accept either kind of message.
                          honestAccepted, forgedAccepted>>

\* ~ means NOT: signing is enabled only when the fresh setup has not been signed.
SignHonest == /\ ~signed
              \* Only an interval-1 sender may create the genuine setup in this model.
              /\ senderNow = 1
              \* Mark the challenged genuine reply as signed; it may then be delayed by the network.
              /\ signed' = TRUE
              \* Signing changes neither clock nor the receiver's installation state.
              /\ UNCHANGED <<senderNow, receiverNow, installed, installedKind,
                             \* It does not record installation or send/buffer an honest message.
                             actualInstalledAt, honestSent, honestBuffered,
                             \* It does not itself authenticate a message or accept a forgery.
                             honestAccepted, forgedAccepted>>

(* Model verification as a cryptographic axiom: the 'check' mode does not
   permit installing an attacker-owned commitment. *)
\* Install a genuine setup only if it was signed, no setup is already installed,
\* and SetupGate permits its arrival time. Signature/challenge validity is idealized
\* by this action, not calculated with real keys or bytes.
InstallValid == /\ signed /\ ~installed /\ SetupGate
                \* Mark a receiver session as installed in the next state.
                /\ installed' = TRUE
                \* Record that its trusted anchor belongs to the genuine sender.
                /\ installedKind' = "genuine"
                \* Remember the real receiver clock at installation, even in legacy mode.
                /\ actualInstalledAt' = receiverNow
                \* Installation changes neither clock nor the fact that a genuine setup was signed.
                /\ UNCHANGED <<senderNow, receiverNow, signed,
                               \* It also leaves honest-message sending and buffering unchanged.
                               honestSent, honestBuffered,
                               \* Installing an anchor alone authenticates neither an honest message nor a forgery.
                               honestAccepted, forgedAccepted>>

(* Deliberately broken signature verification, for counterexample control. *)
\* Allow attacker setup only after the signed phase, with no existing installation,
\* and when signature checking is deliberately bypassed. Check mode disables this action.
InstallAttacker == /\ signed /\ ~installed /\ SigMode = "bypass"
                   \* The same setup-time gate still applies, isolating the broken signature check.
                   /\ SetupGate
                   \* Mark a setup as installed despite it being attacker-controlled.
                   /\ installed' = TRUE
                   \* Remember the attacker label so AuthenticatedAnchor can detect this failure.
                   /\ installedKind' = "attacker"
                   \* Record the true receiver time of this bad installation.
                   /\ actualInstalledAt' = receiverNow
                   \* Keep clocks and the signed-phase flag unchanged by this installation.
                   /\ UNCHANGED <<senderNow, receiverNow, signed,
                                  \* Keep honest-message sending and buffering unchanged.
                                  honestSent, honestBuffered,
                                  \* The bad anchor is detected at setup; this step does not need to accept a message.
                                  honestAccepted, forgedAccepted>>

(* Deliberately broken receiver challenge verification. *)
\* Allow an old setup replay only after the signed phase, before installation,
\* and when the challenge check is bypassed. A saved reply is not fresh merely
\* because its signature is valid; it must match the current receiver challenge.
InstallOldReplay == /\ signed /\ ~installed /\ NonceMode = "bypass"
                    \* Still require the setup-time gate; this control isolates challenge freshness.
                    /\ SetupGate
                    \* Mark the replayed setup as installed.
                    /\ installed' = TRUE
                    \* Record the old-replay label so the freshness invariant can find the violation.
                    /\ installedKind' = "old-replay"
                    \* Keep the real receiver installation time even though this reply is stale.
                    /\ actualInstalledAt' = receiverNow
                    \* Installation does not advance clocks or change the signed-phase flag.
                    /\ UNCHANGED <<senderNow, receiverNow, signed,
                                   \* It does not send or buffer an honest message.
                                   honestSent, honestBuffered,
                                   \* It does not directly change message-acceptance flags.
                                   honestAccepted, forgedAccepted>>

\* Send the single honest message only once and only during sender interval 1.
\* This step need not wait for receiver setup; network timing can interleave freely.
SendHonest == /\ ~honestSent /\ senderNow = 1
              \* Remember that the honest message is now available for delivery.
              /\ honestSent' = TRUE
              \* Sending does not change clocks, setup signing, or whether a session is installed.
              /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                             \* It also preserves setup kind/time and the existing buffer flag.
                             installedKind, actualInstalledAt, honestBuffered,
                             \* Sending alone is not acceptance of either an honest message or a forgery.
                             honestAccepted, forgedAccepted>>

\* BufferHonest requires an installed genuine anchor; an attacker or old-replay
\* setup does not enable this honest-message path.
BufferHonest == /\ installed /\ installedKind = "genuine"
                \* The message must have been sent, not already buffered, and allowed by PacketGate.
                /\ honestSent /\ ~honestBuffered /\ PacketGate
                \* Store the honest-message candidate for later key disclosure and authentication.
                /\ honestBuffered' = TRUE
                \* Buffering does not change either clock or the signed/installed flags.
                /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                               \* It preserves the installed anchor kind/time and the fact the message was sent.
                               installedKind, actualInstalledAt, honestSent,
                               \* Storage alone must not set either acceptance flag.
                               honestAccepted, forgedAccepted>>

\* Authenticate only a buffered honest message that has not already been accepted.
AuthenticateHonest == /\ honestBuffered /\ ~honestAccepted
                      \* Sender time must reach key 1's public-release time.
                      /\ senderNow >= 1 + Delay
                      \* Receiver time must also reach that deadline before honest verification is allowed.
                      /\ receiverNow >= 1 + Delay
                      \* Set the honest-acceptance flag, idealizing successful key and tag checking.
                      /\ honestAccepted' = TRUE
                      \* Authentication itself does not move time or alter the setup/signing flags.
                      /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                                     \* Preserve the installed anchor kind and original installation time.
                                     installedKind, actualInstalledAt,
                                     \* Keep send/buffer history and the independent forged-acceptance flag unchanged.
                                     honestSent, honestBuffered, forgedAccepted>>

(* The adversary knows K1 as soon as its disclosure time passes, even if
   the receiver has not yet seen the network disclosure. *)
\* Model an attacker using a publicly released key against a genuinely installed
\* anchor. This combines forgery admission/acceptance into one symbolic event;
\* it does not reproduce Python's detailed buffering and disclosure-processing steps.
AcceptForgedAfterRelease == /\ installed /\ installedKind = "genuine"
                            \* Record at most one such attack acceptance in the finite state space.
                            /\ ~forgedAccepted
                            \* The attacker first needs sender time to reach public release of key 1.
                            /\ senderNow >= 1 + Delay
                            \* The receiver's admission gate must still be open. A safe live bound prevents
                            \* this overlap; a stale clock or understated bound can incorrectly leave it open.
                            /\ PacketGate
                            \* Remember that the released-key forgery was accepted, violating NoReleasedForgery.
                            /\ forgedAccepted' = TRUE
                            \* This attack event leaves both clocks and setup/signing status unchanged.
                            /\ UNCHANGED <<senderNow, receiverNow, signed, installed,
                                           \* It cannot replace the installed genuine anchor or rewrite its installation time.
                                           installedKind, actualInstalledAt,
                                           \* It does not need to send, buffer, or accept an honest message.
                                           honestSent, honestBuffered, honestAccepted>>

\* Next permits any enabled action via OR, not a fixed sequence. Time may tick,
\* the receiver may catch up, or the honest sender may sign the setup.
Next == Tick \/ CatchUp \/ SignHonest
        \* A genuine, attacker, or replayed setup may be installed when its own guards allow.
        \/ InstallValid \/ InstallAttacker \/ InstallOldReplay
        \* An honest message may be sent, buffered, or authenticated as a separate possible step.
        \/ SendHonest \/ BufferHonest \/ AuthenticateHonest
        \* A released-key forgery may also be accepted when that action's guards permit it.
        \/ AcceptForgedAfterRelease

\* Spec begins with Init and then always ([]) permits Next or no change to vars.
\* [Next]_vars allows such no-change steps, called stuttering. No fairness is
\* required: no action, delivery, or clock progress is promised to happen eventually.
Spec == Init /\ [][Next]_vars

\* TypeOK checks state shapes and basic consistency in every reachable state.
\* Require sender time to stay within the finite Times set.
TypeOK == /\ senderNow \in Times
          \* Require receiver time in that same finite range.
          /\ receiverNow \in Times
          \* The receiver must never run ahead of the sender.
          /\ receiverNow <= senderNow
          \* Its actual lag must respect the selected Lag limit.
          /\ senderNow - receiverNow <= Lag
          \* BOOLEAN is {TRUE, FALSE}: signed must be one of these two truth values.
          /\ signed \in BOOLEAN
          \* The installed flag must likewise be a Boolean.
          /\ installed \in BOOLEAN
          \* The installed setup kind must be one of the four allowed labels.
          /\ installedKind \in Kinds
          \* \cup forms a set union: installation time may be zero before setup, or any allowed clock time.
          /\ actualInstalledAt \in {0} \cup Times
          \* The honest-message-sent flag must be Boolean.
          /\ honestSent \in BOOLEAN
          \* The buffered-message flag must be Boolean.
          /\ honestBuffered \in BOOLEAN
          \* The genuine-acceptance flag must be Boolean.
          /\ honestAccepted \in BOOLEAN
          \* The forgery-acceptance flag must be Boolean.
          /\ forgedAccepted \in BOOLEAN
          \* # means not equal in TLA+, unlike Python comments. Require installed to be
          \* true exactly when the kind is something other than none.
          /\ installed = (installedKind # "none")
          \* => means implies: a buffered honest message must already have been sent.
          /\ honestBuffered => honestSent
          \* An accepted honest message must already have been buffered. The flags retain
          \* history, so the model does not clear honestBuffered after successful checking.
          /\ honestAccepted => honestBuffered

\* Security rule: the installed anchor must never belong to the attacker.
\* No installation yet satisfies this rule; the broken-signature config must violate it.
AuthenticatedAnchor == installedKind # "attacker"
\* Security rule: no installed setup may be an old challenge reply. The broken
\* challenge-check config deliberately reaches the forbidden old-replay label.
ChallengeFreshness == installedKind # "old-replay"
\* Security rule: the forged-acceptance flag must stay false; ~ negates the Boolean.
NoReleasedForgery == ~forgedAccepted
\* If an honest message has authenticated, sender time must have reached key release.
HonestAfterDisclosure == honestAccepted => senderNow >= 1 + Delay
\* For installed live-clock sessions only, require the following setup-time condition.
\* => imposes no condition on legacy mode or a state before setup is installed.
LiveSetupBeforeDisclosure == (ClockMode = "live" /\ installed) =>
    \* Use the remembered actual installation time plus the margin, not today's
    \* clock, to prove that this setup passed before the first possible key release.
    actualInstalledAt + Bound < 1 + Delay

(* Deliberately false liveness-style witness: a real message can authenticate. *)
\* This deliberately false invariant says no honest message can authenticate.
\* Its expected counterexample is a witness: one allowed history that does authenticate.
\* That checks useful reachability, not eventual success in all histories, since
\* the network may delay forever. Other unexpected rule failures remain real errors.
NoHonestAuthentication == ~honestAccepted

\* This equals-sign boundary closes the TLA+ module.
=============================================================================
