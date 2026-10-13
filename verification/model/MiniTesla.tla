\* This module describes possible states and steps; it is not Python and does
\* not run top to bottom. TLC explores every allowed next step in the chosen
\* finite configuration. A state is one complete set of variable values.
\* A backslash followed by * starts a line comment. Parentheses with * delimit
\* block comments, such as the existing description below. Neither changes the model.
\* MODULE names the model; the matching filename is MiniTesla.tla.
----------------------------- MODULE MiniTesla -----------------------------
\* Load standard definitions for natural numbers (0, 1, ...), all integers,
\* ordered sequences, finite sets, and TLC helper operations.
EXTENDS Naturals, Integers, Sequences, FiniteSets, TLC

(***************************************************************************
 An independent, finite, symbolic model of delayed key authentication.
 It is intentionally not a translation of the implementation/checker.

 A key is represented by its chain index. K[0] is the public commitment.
 H(K[i]) = K[i-1]: learning a higher-index key reveals LOWER-index keys.
 AnchorCheck assumes distinct, collision-free symbolic chain keys; it is
 NOT a proof of computational hash one-wayness or MAC unforgeability.

 Time is sender time. Disclosure becomes public at i + Delay even when
 the adversary withholds that disclosure from the receiver. Lag and Bound
 separately represent maximum actual receiver lag and the error bound
 used by its admission guard. The receiver may catch up independently.
 A safe admission test must use an upper bound on sender time.

 Genuine packets become network-available only after Send in interval i.
 Invalid-tag packets are always available. Forged packets with valid tags
 become available only after the matching key is public. Replayed genuine
 packets retain the genuine payload. All network choices are adversarial.

 BufferCapacity and two copies bound the state space. Full-buffer arrivals
 are dropped. Processing/disclosure delivery may be withheld forever, so
 no liveness or availability property is claimed.
***************************************************************************)

\* Constants stay fixed for a run and get values from a .cfg file. N counts key
\* intervals; Delay is the wait until a key is public; Lag bounds actual clock lag;
\* Bound is the sender-ahead margin used by admission. BufferCapacity limits
\* stored receipts, and GuardMode chooses the safe or deliberately unsafe guard.
CONSTANTS N, Delay, Lag, Bound, BufferCapacity, GuardMode
\* ASSUME restricts valid constant choices. /\ means AND: every listed clause
\* must hold. \in means belongs to; Nat \ {0} removes zero, so N must be positive.
ASSUME /\ N \in Nat \ {0}
       \* Require a positive key-release delay: no message key is released immediately.
       /\ Delay \in Nat \ {0}
       \* Allow zero or positive actual receiver lag; clocks never need a negative lag limit.
       /\ Lag \in Nat
       \* Allow zero or positive admission margins. No assumption here requires Bound
       \* to cover Lag: some configs deliberately understate it to expose an attack.
       /\ Bound \in Nat
       \* Require room for at least one buffered receipt so the configured buffer is meaningful.
       /\ BufferCapacity \in Nat \ {0}
       \* Only these two quoted mode names are legal: deadline checks time; delivery
       \* checks whether the receiver has obtained a key, which is intentionally unsafe.
       /\ GuardMode \in {"deadline", "delivery"}

\* == defines a named expression. 1..N is the inclusive set of key/message
\* intervals from 1 through N, not a loop or a changing variable.
Intervals == 1..N
\* End the finite time horizon when the final interval key can be released.
LastTime == N + Delay
\* Include time zero before sending begins, through the final disclosure time.
Times == 0..LastTime
\* Use two copy labels, enabling duplicate-arrival traces while bounding choices.
\* The buffer also records arrival time, so these are labels, not a global two-arrival limit.
Copies == 1..2
\* A set uses braces. Model genuine traffic, always-invalid tags, and attacker
\* forgeries whose tags become valid once their key is public. These are symbolic
\* labels, not real payload bytes or cryptographic calculations.
Kinds == {"Genuine", "Invalid", "Forged"}
\* [field : Set, ...] means all records with those fields drawn from those sets.
\* Each possible packet carries an interval i and one of the three kind labels.
Packets == [i : Intervals, kind : Kinds]
\* Each receipt records the packet, actual sender time of arrival, and copy label.
\* Keeping arrival time lets us later check secrecy at receipt, not only at verification.
Receipts == [packet : Packets, arrived : Times, copy : Copies]
\* An authentication-log event stores its receipt, checking time, and key interval.
AuthEvents == [receipt : Receipts, checkedAt : Times, key : Intervals]
(* Index -1 denotes an arbitrary invalid key; index 0 is public K[0]. *)
\* Allow invalid key -1, public anchor 0, and symbolic chain keys 1 through N.
\* The parenthesized -1 is a negative integer, not a real byte-string key.
KeyValues == (-1)..N
\* Describe key-check records: claimed interval, supplied symbolic key, and a
\* Boolean result. BOOLEAN contains TRUE and FALSE. Claim zero is used in Init.
KeyEvents == [claim : 0..N, value : KeyValues, accepted : BOOLEAN]

\* {i \in Intervals : condition} keeps only elements satisfying that condition.
\* A key is released at i + Delay, including the exact deadline (<= means at most).
Released(t) == {i \in Intervals : i + Delay <= t}
\* Knowing key i also reveals keys j at or below i by repeated hashing toward
\* the public anchor. This set contains only message intervals, excluding key zero.
Lower(i) == {j \in Intervals : j <= i}
\* UNION merges all the Lower(i) sets for released keys. Public knowledge grows
\* when sender time passes a deadline even if network delivery to this receiver is blocked.
PublicKeys(t) == UNION {Lower(i) : i \in Released(t)}

(* Symbolic validation of H^claim(K[value]) against K[0]. *)
\* = tests equality; == defines the check. Matching claimed and actual key
\* indices idealizes hashing the key back to anchor K[0]. An anchor is the trusted
\* public endpoint of the chain. Collision-free linkage and one-way hashing are
\* assumed here, not proved or implemented with real hashes.
AnchorCheck(claim, value) == claim = value
\* The dot reads a record field. Genuine and forged packets have matching tags;
\* invalid packets do not. Availability, not this predicate, stops early forgeries.
CorrectTag(p) == p.kind \in {"Genuine", "Forged"}
\* <<...>> forms an ordered tuple. Identify a message by interval and source class.
\* IF/THEN/ELSE chooses honest for genuine traffic, attacker for both other kinds.
\* This omits real sequence numbers and same-identity honest/attacker collisions.
Identity(p) == <<p.i, IF p.kind = "Genuine" THEN "honest" ELSE "attacker">>

\* VARIABLES change between states: the two clocks, sent interval set, receiver
\* known-key set, receipt buffer, ordered acceptance log, last key-check record,
\* and a flag recording whether any correct-tag replay was suppressed.
VARIABLES now, receiverNow, sent, known, buffer, authLog, lastKey, replayIgnored
\* Group every state variable in one tuple for the temporal specification below.
\* The name vars is a defined expression, not an additional state variable.
vars == <<now, receiverNow, sent, known, buffer, authLog, lastKey, replayIgnored>>
\* Receiver time plus Bound estimates the latest possible sender time. It is a
\* valid upper bound only when the configured margin covers actual clock lag.
UpperSenderTime == receiverNow + Bound
\* Map every log entry to its identity and collect the results into a set.
\* Sequences are indexed from 1; Len gives their length. An empty log yields
\* no indices and an empty identity set; sets keep each identity only once.
AcceptedIds == {Identity(authLog[n].receipt.packet) : n \in 1..Len(authLog)}

\* Init defines the starting state by AND-ing all these equalities. Sender time
\* starts at zero, before the first message interval.
Init == /\ now = 0
        \* Start receiver time at zero as well, with no initial lag.
        /\ receiverNow = 0
        \* The empty set {} means no genuine interval has been sent.
        /\ sent = {}
        \* The receiver initially knows no message keys; the public anchor is handled separately.
        /\ known = {}
        \* No arrivals are waiting for key verification.
        /\ buffer = {}
        \* <<>> is an empty ordered sequence: no packets have been authenticated yet.
        /\ authLog = <<>>
        \* [name |-> value, ...] builds one record, unlike [name : Set] above.
        \* Use a dummy anchor-zero check marked FALSE, so it claims no accepted key delivery.
        /\ lastKey = [claim |-> 0, value |-> 0, accepted |-> FALSE]
        \* No buffered replay has been suppressed at the start.
        /\ replayIgnored = FALSE

\* Tick is an action, a relation between one state and the next. It is allowed
\* only before the finite horizon. A false guard disables this step, not the whole run.
Tick == /\ now < LastTime
        \* A prime (now') means the next-state value. Increase sender time by one; all
        \* clauses of the action constrain the same step, not separate sequential instructions.
        /\ now' = now + 1
        \* Choose any next receiver time r satisfying the following set conditions.
        \* TLC explores all allowed choices, not one randomly selected receiver clock.
        /\ receiverNow' \in {r \in Times :
              \* Require r to be at least the old receiver time: the clock never moves backward.
              /\ receiverNow <= r
              \* Do not let the receiver get ahead of the new sender time.
              /\ r <= now + 1
              \* Require the new sender/receiver difference to be no greater than Lag.
              /\ now + 1 - r <= Lag}
        \* UNCHANGED preserves all non-clock state. Advancing time makes keys publicly
        \* knowable by definition, but does not pretend the receiver has received them.
        /\ UNCHANGED <<sent, known, buffer, authLog, lastKey, replayIgnored>>

\* Allow a separate catch-up step only while receiver time trails sender time.
CatchUp == /\ receiverNow < now
           \* Move receiver time ahead by one without advancing the sender.
           /\ receiverNow' = receiverNow + 1
           \* Keep sender time, messages, keys, buffered receipts, log, and replay flag fixed.
           /\ UNCHANGED <<now, sent, known, buffer, authLog, lastKey, replayIgnored>>

\* Send(i) represents the honest sender transmitting interval i only at time i.
Send(i) == /\ now = i
           \* \notin means does not belong to: require this interval not to have been sent already.
           /\ i \notin sent
           \* \cup means set union; add i to the sent set so genuine packets for it become available.
           /\ sent' = sent \cup {i}
           \* Sending alone changes no clocks, receiver keys, receipts, verification log, or replay state.
           /\ UNCHANGED <<now, receiverNow, known, buffer, authLog, lastKey, replayIgnored>>

\* CASE selects a rule by packet kind; -> separates its condition from its result.
\* A genuine packet is available on the network only after its interval was sent.
Available(p) == CASE p.kind = "Genuine" -> p.i \in sent
                 \* [] separates CASE branches. An attacker can always offer a packet with an invalid tag.
                 [] p.kind = "Invalid" -> TRUE
                 \* A valid-tag forgery becomes available only when its key belongs to public knowledge.
                 \* This assumes tags cannot be forged before release; it does not prove that assumption.
                 [] p.kind = "Forged" -> p.i \in PublicKeys(now)

\* SafeToBuffer is a condition, not a step: the packet must not claim a time
\* in the receiver's future. Buffering stores an untrusted candidate for later checking.
SafeToBuffer(p) == /\ p.i <= receiverNow
                   \* Choose the guard according to the constant mode selected in the configuration.
                   /\ IF GuardMode = "deadline"
                         \* The deadline guard requires even the latest possible sender time to be
                         \* strictly before release. Equality is unsafe because the key may already be public.
                         THEN UpperSenderTime < p.i + Delay
                         \* The delivery guard asks only whether this receiver lacks the key. It is a
                         \* negative control: withholding an already-public disclosure defeats this test.
                         ELSE p.i \notin known

\* Receive describes a permitted arrival that is actually admitted to the buffer.
\* Rejected or full-buffer arrivals need no state change and are not separate actions.
Receive(p, copy) ==
  \* LET defines a local name r used after IN: record this packet, its true sender
  \* arrival time, and chosen copy label. The record is fixed for this candidate receipt.
  LET r == [packet |-> p, arrived |-> now, copy |-> copy] IN
  \* Require the packet to be available under the honest-send/public-key assumptions.
  /\ Available(p)
  \* Require the chosen time or delivery guard to allow admission.
  /\ SafeToBuffer(p)
  \* Do not admit any message identity already present in the authentication log.
  /\ Identity(p) \notin AcceptedIds
  \* Cardinality counts set elements; require space before adding the receipt.
  /\ Cardinality(buffer) < BufferCapacity
  \* Do not add an identical receipt record twice. A different copy label or arrival
  \* time can still model another buffered copy of the same message identity.
  /\ r \notin buffer
  \* Add this one receipt to the next buffer using set union.
  /\ buffer' = buffer \cup {r}
  \* An arrival updates only the buffer; it cannot immediately authenticate a message.
  /\ UNCHANGED <<now, receiverNow, sent, known, authLog, lastKey, replayIgnored>>

(* No delivery fairness: public keys need never reach this receiver. *)
\* DeliverKey lets the network offer a claimed interval and supplied symbolic key.
\* No fairness means this action may be postponed forever: public does not mean delivered.
DeliverKey(claim, value) ==
  \* Receiver time must reach the claimed key's disclosure deadline before this check.
  /\ receiverNow >= claim + Delay
  \* The network may supply an arbitrary bad key, the public anchor, or any publicly
  \* derivable message key. It cannot deliver a still-secret genuine key early.
  /\ value \in {-1, 0} \cup PublicKeys(now)
  \* Record the claimed interval and the key that was actually supplied in the next state.
  /\ lastKey' = [claim |-> claim, value |-> value,
                 \* Store the symbolic anchor-check result, even when the delivery is rejected.
                 accepted |-> AnchorCheck(claim, value)]
  \* Change receiver knowledge only if the claimed interval matches the supplied key.
  /\ known' = IF AnchorCheck(claim, value)
              \* For a valid key, add it and all lower-index keys derivable by hashing.
              THEN known \cup Lower(value)
              \* For an invalid key, preserve receiver knowledge exactly as it was.
              ELSE known
  \* Key delivery changes only known keys and the last-check record, not the buffer
  \* or log. Packet checking is a separate model action, unlike a combined Python batch.
  /\ UNCHANGED <<now, receiverNow, sent, buffer, authLog, replayIgnored>>

\* Verify models checking one buffered receipt after its message key is known.
Verify(r) ==
  \* Require this particular receipt still to be waiting in the buffer.
  /\ r \in buffer
  \* Require the receiver to know the packet interval's key; public-but-undelivered is insufficient.
  /\ r.packet.i \in known
  \* \ removes set members: take this receipt out whether its tag passes or fails.
  /\ buffer' = buffer \ {r}
  \* Log an acceptance only for a correct tag AND an identity not accepted before.
  \* A forged tag may be correct after release, which is why the earlier time guard matters.
  /\ authLog' = IF CorrectTag(r.packet) /\ Identity(r.packet) \notin AcceptedIds
                \* Append adds an event at the end of the log, preserving the receipt and actual check time.
                THEN Append(authLog, [receipt |-> r, checkedAt |-> now,
                                      \* Record use of the key for this packet's own interval, not another chain position.
                                      key |-> r.packet.i])
                \* Invalid-tag or already-accepted packets do not add a new acceptance event.
                ELSE authLog
  \* \/ means OR: once replayIgnored is true it stays true on later verification steps.
  /\ replayIgnored' = (replayIgnored \/
                       \* Also set the flag when a correct-tag receipt repeats a previously accepted identity.
                       \* This makes a duplicate-suppression example detectable by the witness invariant.
                       (CorrectTag(r.packet) /\ Identity(r.packet) \in AcceptedIds))
  \* Verification does not change either clock, sent intervals, known keys, or the last key check.
  /\ UNCHANGED <<now, receiverNow, sent, known, lastKey>>

\* Next permits any one enabled action. The OR list does not impose an execution
\* order: the network and timing choices can interleave adversarially. First option: Tick.
Next == Tick
     \* Another possible step is receiver catch-up without sender movement.
     \/ CatchUp
     \* \E means there exists: choose any interval whose honest Send action is enabled.
     \/ (\E i \in Intervals : Send(i))
     \* Choose any packet and copy label whose Receive conditions all hold.
     \/ (\E p \in Packets, copy \in Copies : Receive(p, copy))
     \* Choose any claimed interval and key value for which a key-delivery step is enabled.
     \/ (\E claim \in Intervals, value \in KeyValues : DeliverKey(claim, value))
     \* Choose any current buffer receipt that is ready for verification.
     \/ (\E r \in buffer : Verify(r))

\* Spec requires Init and then always ([]) either a Next step or no change to vars.
\* [Next]_vars permits that no-change step, called stuttering. No fairness condition
\* forces sending, delivery, time advance, or verification eventually to happen.
Spec == Init /\ [][Next]_vars

\* TypeOK is an invariant: a rule checked at every reached state when listed in
\* a .cfg file. Begin by requiring sender time inside the finite Times set.
TypeOK == /\ now \in Times
          \* Require receiver time in the same finite range.
          /\ receiverNow \in Times
          \* The receiver must never be ahead of the sender.
          /\ receiverNow <= now
          \* The actual clock lag must never exceed the configured maximum.
          /\ now - receiverNow <= Lag
          \* \subseteq means every element on the left belongs to the right: sent holds only valid intervals.
          /\ sent \subseteq Intervals
          \* Receiver-known keys must all be message-key indices in the modeled chain.
          /\ known \subseteq Intervals
          \* Every buffered element must have the receipt fields and permitted value ranges.
          /\ buffer \subseteq Receipts
          \* Never store more receipt records than the configured buffer capacity.
          /\ Cardinality(buffer) <= BufferCapacity
          \* Seq(AuthEvents) is the set of finite ordered sequences of valid authentication events.
          /\ authLog \in Seq(AuthEvents)
          \* Allow at most two accepted identities per interval: one honest and one attacker.
          \* This bound accompanies the replay rule and keeps the acceptance history finite.
          /\ Len(authLog) <= 2 * N
          \* Require the last key-check record to have valid claim, value, and Boolean fields.
          /\ lastKey \in KeyEvents
          \* Require the replay-suppression flag to be exactly TRUE or FALSE.
          /\ replayIgnored \in BOOLEAN

\* KeyValidation first forbids receiver knowledge of any key not publicly derivable yet.
KeyValidation == /\ known \subseteq PublicKeys(now)
                 \* \A means for every: whenever a key is known, all its hash-derivable lower
                 \* keys must be known too. This is a symbolic-model assumption about derivation.
                 /\ \A i \in known : Lower(i) \subseteq known
                 \* => means if the left is true, the right must be true. A recorded accepted
                 \* key check must match the trusted anchor; rejected checks create no such obligation.
                 /\ lastKey.accepted => AnchorCheck(lastKey.claim, lastKey.value)

\* For every accepted log entry, require both of the following source checks.
\* When the log is empty there is no counterexample; witness configs check useful acceptance too.
SourceAuthentication == \A n \in 1..Len(authLog) :
    \* The accepted packet must be genuine, not an invalid-tag packet or a valid-tag forgery.
    /\ authLog[n].receipt.packet.kind = "Genuine"
    \* Its interval must actually have been sent by the honest sender.
    /\ authLog[n].receipt.packet.i \in sent

\* Check secrecy at arrival for every accepted log entry, even if checking happened much later.
ArrivalWhileSecret == \A n \in 1..Len(authLog) :
    \* The packet's key must not have been public at the receipt's recorded sender time.
    \* The nested dots follow event -> receipt -> packet fields; [n] selects log entry n.
    authLog[n].receipt.packet.i \notin PublicKeys(authLog[n].receipt.arrived)

\* For every logged acceptance, check tag validity, key selection, and receiver knowledge.
CorrectAuthentication == \A n \in 1..Len(authLog) :
    \* The packet must have a symbolically correct tag.
    /\ CorrectTag(authLog[n].receipt.packet)
    \* The recorded verification key must match the message's own interval.
    /\ authLog[n].key = authLog[n].receipt.packet.i
    \* That key must belong to the receiver's known-key set.
    /\ authLog[n].key \in known

\* For every accepted event, check that actual authentication was not premature.
NoEarlyAcceptance == \A n \in 1..Len(authLog) :
    \* The recorded checking time must be at or after that interval's key-release time.
    authLog[n].checkedAt >= authLog[n].receipt.packet.i + Delay

\* A set removes duplicate identities, while a sequence keeps every event. Equal
\* counts mean no identity appears twice in the acceptance log, preventing repeated acceptance.
NoReplay == Len(authLog) = Cardinality(AcceptedIds)

(* Deliberately false diagnostic invariants: witness that checks are useful. *)
\* ~ means NOT. This deliberately claims that no genuine acceptance exists.
\* A counterexample disproves it by showing useful authentication is reachable;
\* that is the intended witness outcome, not a failure of the real safety rules.
NoHonestAcceptance == ~\E n \in 1..Len(authLog) :
    \* The witness searches the log for an accepted Genuine packet.
    authLog[n].receipt.packet.kind = "Genuine"
\* This deliberately claims replay suppression has never occurred. Its expected
\* violation demonstrates the duplicate-handling path is reachable. It does not
\* claim that all executions will eventually perform that path.
NoReplaySuppression == ~replayIgnored

\* The equals-sign boundary ends the TLA+ module.
=============================================================================
