----------------------------- MODULE MiniTesla -----------------------------
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

CONSTANTS N, Delay, Lag, Bound, BufferCapacity, GuardMode
ASSUME /\ N \in Nat \ {0}
       /\ Delay \in Nat \ {0}
       /\ Lag \in Nat
       /\ Bound \in Nat
       /\ BufferCapacity \in Nat \ {0}
       /\ GuardMode \in {"deadline", "delivery"}

Intervals == 1..N
LastTime == N + Delay
Times == 0..LastTime
Copies == 1..2
Kinds == {"Genuine", "Invalid", "Forged"}
Packets == [i : Intervals, kind : Kinds]
Receipts == [packet : Packets, arrived : Times, copy : Copies]
AuthEvents == [receipt : Receipts, checkedAt : Times, key : Intervals]
(* Index -1 denotes an arbitrary invalid key; index 0 is public K[0]. *)
KeyValues == (-1)..N
KeyEvents == [claim : 0..N, value : KeyValues, accepted : BOOLEAN]

Released(t) == {i \in Intervals : i + Delay <= t}
Lower(i) == {j \in Intervals : j <= i}
PublicKeys(t) == UNION {Lower(i) : i \in Released(t)}

(* Symbolic validation of H^claim(K[value]) against K[0]. *)
AnchorCheck(claim, value) == claim = value
CorrectTag(p) == p.kind \in {"Genuine", "Forged"}
Identity(p) == <<p.i, IF p.kind = "Genuine" THEN "honest" ELSE "attacker">>

VARIABLES now, receiverNow, sent, known, buffer, authLog, lastKey, replayIgnored
vars == <<now, receiverNow, sent, known, buffer, authLog, lastKey, replayIgnored>>
UpperSenderTime == receiverNow + Bound
AcceptedIds == {Identity(authLog[n].receipt.packet) : n \in 1..Len(authLog)}

Init == /\ now = 0
        /\ receiverNow = 0
        /\ sent = {}
        /\ known = {}
        /\ buffer = {}
        /\ authLog = <<>>
        /\ lastKey = [claim |-> 0, value |-> 0, accepted |-> FALSE]
        /\ replayIgnored = FALSE

Tick == /\ now < LastTime
        /\ now' = now + 1
        /\ receiverNow' \in {r \in Times :
              /\ receiverNow <= r
              /\ r <= now + 1
              /\ now + 1 - r <= Lag}
        /\ UNCHANGED <<sent, known, buffer, authLog, lastKey, replayIgnored>>

CatchUp == /\ receiverNow < now
           /\ receiverNow' = receiverNow + 1
           /\ UNCHANGED <<now, sent, known, buffer, authLog, lastKey, replayIgnored>>

Send(i) == /\ now = i
           /\ i \notin sent
           /\ sent' = sent \cup {i}
           /\ UNCHANGED <<now, receiverNow, known, buffer, authLog, lastKey, replayIgnored>>

Available(p) == CASE p.kind = "Genuine" -> p.i \in sent
                 [] p.kind = "Invalid" -> TRUE
                 [] p.kind = "Forged" -> p.i \in PublicKeys(now)

SafeToBuffer(p) == /\ p.i <= receiverNow
                   /\ IF GuardMode = "deadline"
                         THEN UpperSenderTime < p.i + Delay
                         ELSE p.i \notin known

Receive(p, copy) ==
  LET r == [packet |-> p, arrived |-> now, copy |-> copy] IN
  /\ Available(p)
  /\ SafeToBuffer(p)
  /\ Identity(p) \notin AcceptedIds
  /\ Cardinality(buffer) < BufferCapacity
  /\ r \notin buffer
  /\ buffer' = buffer \cup {r}
  /\ UNCHANGED <<now, receiverNow, sent, known, authLog, lastKey, replayIgnored>>

(* No delivery fairness: public keys need never reach this receiver. *)
DeliverKey(claim, value) ==
  /\ receiverNow >= claim + Delay
  /\ value \in {-1, 0} \cup PublicKeys(now)
  /\ lastKey' = [claim |-> claim, value |-> value,
                 accepted |-> AnchorCheck(claim, value)]
  /\ known' = IF AnchorCheck(claim, value)
              THEN known \cup Lower(value)
              ELSE known
  /\ UNCHANGED <<now, receiverNow, sent, buffer, authLog, replayIgnored>>

Verify(r) ==
  /\ r \in buffer
  /\ r.packet.i \in known
  /\ buffer' = buffer \ {r}
  /\ authLog' = IF CorrectTag(r.packet) /\ Identity(r.packet) \notin AcceptedIds
                THEN Append(authLog, [receipt |-> r, checkedAt |-> now,
                                      key |-> r.packet.i])
                ELSE authLog
  /\ replayIgnored' = (replayIgnored \/
                       (CorrectTag(r.packet) /\ Identity(r.packet) \in AcceptedIds))
  /\ UNCHANGED <<now, receiverNow, sent, known, lastKey>>

Next == Tick
     \/ CatchUp
     \/ (\E i \in Intervals : Send(i))
     \/ (\E p \in Packets, copy \in Copies : Receive(p, copy))
     \/ (\E claim \in Intervals, value \in KeyValues : DeliverKey(claim, value))
     \/ (\E r \in buffer : Verify(r))

Spec == Init /\ [][Next]_vars

TypeOK == /\ now \in Times
          /\ receiverNow \in Times
          /\ receiverNow <= now
          /\ now - receiverNow <= Lag
          /\ sent \subseteq Intervals
          /\ known \subseteq Intervals
          /\ buffer \subseteq Receipts
          /\ Cardinality(buffer) <= BufferCapacity
          /\ authLog \in Seq(AuthEvents)
          /\ Len(authLog) <= 2 * N
          /\ lastKey \in KeyEvents
          /\ replayIgnored \in BOOLEAN

KeyValidation == /\ known \subseteq PublicKeys(now)
                 /\ \A i \in known : Lower(i) \subseteq known
                 /\ lastKey.accepted => AnchorCheck(lastKey.claim, lastKey.value)

SourceAuthentication == \A n \in 1..Len(authLog) :
    /\ authLog[n].receipt.packet.kind = "Genuine"
    /\ authLog[n].receipt.packet.i \in sent

ArrivalWhileSecret == \A n \in 1..Len(authLog) :
    authLog[n].receipt.packet.i \notin PublicKeys(authLog[n].receipt.arrived)

CorrectAuthentication == \A n \in 1..Len(authLog) :
    /\ CorrectTag(authLog[n].receipt.packet)
    /\ authLog[n].key = authLog[n].receipt.packet.i
    /\ authLog[n].key \in known

NoEarlyAcceptance == \A n \in 1..Len(authLog) :
    authLog[n].checkedAt >= authLog[n].receipt.packet.i + Delay

NoReplay == Len(authLog) = Cardinality(AcceptedIds)

(* Deliberately false diagnostic invariants: witness that checks are useful. *)
NoHonestAcceptance == ~\E n \in 1..Len(authLog) :
    authLog[n].receipt.packet.kind = "Genuine"
NoReplaySuppression == ~replayIgnored

=============================================================================
