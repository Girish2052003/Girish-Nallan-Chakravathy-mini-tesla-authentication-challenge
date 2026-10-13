# Bootstrap means the first setup that lets a receiver trust a sender.
# This script checks a small grid of clock values with real signing code.
# A # line explains the program; Python does not run it. The quoted text below
# is a module docstring, a description kept by Python. These comments do not
# turn this finite set of examples into a proof for every possible situation.
"""Bounded implementation grid for challenge-signed bootstrap time admission.

Tests actual Ed25519 signatures and Python ReceiverBootstrap; not a formal
proof of the signatures or a refinement proof of the TLA+ model.
"""
# Keep type annotations, such as -> None below, as deferred descriptions.
# An import makes another module or named object available to this file.
from __future__ import annotations
# Load the secure-randomness module; this script does not directly use it.
import secrets
# Load Ed25519 private keys: secret signing keys whose public half checks signatures.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# Load the receiver setup, sender, expected rejection error, and setup-signing helper.
from mini_tesla import ReceiverBootstrap, Satellite, SetupRejected, sign_satellite_setup


# Define the function that runs the grid; -> None says it returns no result value.
# Indented lines belong to this function; deeper indentation marks nested work.
def main() -> None:
    # Count all completed clock combinations, including expected rejections.
    count = 0
    # Count setups admitted before the first key could be public.
    passed = 0
    # Count setups rejected because the possible disclosure time has arrived.
    rejected = 0
    # Repeat for delays 1, 2, and 3; range stops before its second number.
    # The delay is the wait from a message interval until its message-authentication key is revealed.
    for delay in range(1, 4):
        # Try clock margins 0, 1, and 2. A margin bounds how far ahead the sender may be.
        for bound in range(3):
            # Try receiver times 1 through delay + 4, on both sides of the setup deadline.
            for now in range(1, delay + 5):
                # Create a fresh five-key sender for each combination so earlier trials cannot affect it.
                satellite = Satellite(chain_length=5, disclosure_delay=delay)
                # Generate a real fresh secret signing key for this setup trial.
                key = Ed25519PrivateKey.generate()
                # Put the trial time in a one-item list that the trusted clock function can read.
                time = [now]
                # Create receiver-side setup state; it creates a fresh challenge to tie the reply
                # to this request. Named arguments state which setting each value supplies.
                bootstrap = ReceiverBootstrap(
                    # Trust the public half of our test signer, not a key supplied inside the reply.
                    trusted_public_key=key.public_key(),
                    # Require this exact sender name when checking the signed setup.
                    expected_satellite_id="test-satellite",
                    # lambda makes a short function: with no argument it returns the list item at
                    # index 0. time=time keeps this trial's list as its default; the list is not changed here.
                    trusted_interval_source=lambda time=time: time[0],
                )
                # Sign the sender's initial setup with the real signing helper.
                signed = sign_satellite_setup(
                    # Supply the fresh sender and the private key that corresponds to the trusted public key.
                    satellite, signing_key=key,
                    # Sign the expected sender name and this receiver's challenge, binding both to the reply.
                    satellite_id="test-satellite", challenge=bootstrap.challenge,
                )
                # Compute the independent expected outcome: now + bound is the latest possible
                # sender time, and 1 + delay is the first key's release time. Equality is already too late.
                safe = now + bound < 1 + delay
                # Attempt setup while allowing the specific expected rejection to be examined.
                try:
                    # Ask the real receiver setup code to verify the reply and apply this clock margin.
                    receiver = bootstrap.establish(signed, max_sender_ahead=bound)
                # Catch only the defined setup rejection; unrelated errors still fail the script.
                except SetupRejected:
                    # A rejection is wrong if the trial was strictly before the safe deadline.
                    if safe:
                        # Stop with the exact failing delay, margin, and time to make the regression diagnosable.
                        raise AssertionError((delay, bound, now, "unexpected rejection"))
                    # Add one expected unsafe-time rejection; += increases the existing count.
                    rejected += 1
                # This else runs only when the try block finished without a setup rejection.
                else:
                    # Check both conditions for success: admission was safe and the receiver kept
                    # the trusted current time. != means unequal; or needs only one bad condition.
                    if not safe or receiver.current_interval != now:
                        # Fail for unsafe admission or a stale initial receiver clock, even with a valid signature.
                        raise AssertionError((delay, bound, now, "unsafe acceptance"))
                    # Count this safe setup only after its clock and admission checks succeed.
                    passed += 1
                # Count the trial after either expected outcome; no failed trial reaches this line.
                count += 1
    # Print the completed grid size; f-strings insert the values inside braces.
    print(f"Bootstrap time grid passed: {count} cases "
          # Continue the same printed message with separate safe and rejected counts.
          f"({passed} admitted, {rejected} rejected)")
    # assert requires a true condition or raises AssertionError: 3 margins times
    # (5 + 6 + 7) clock choices must give 54 trials. Run without Python -O, which skips asserts.
    assert count == 54

# Run the grid only when this file is launched directly; importing it just defines main.
if __name__ == "__main__":
    # Call the function that carries out every setup-time trial.
    main()
