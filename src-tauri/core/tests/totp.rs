//! TOTP cycle geometry: the period a secret declares must survive into the
//! value the session hands to the UI, so a cycle ring can be truthful.

use kestrel_core::totp;

#[test]
fn bare_secret_uses_the_thirty_second_default() {
    let current = totp::code_now("JBSWY3DPEHPK3PXP").expect("valid secret");
    assert_eq!(current.period, 30);
    assert!(
        current.seconds_remaining >= 1 && current.seconds_remaining <= current.period,
        "remaining must sit inside one declared cycle"
    );
}

#[test]
fn otpauth_period_is_honoured() {
    let current =
        totp::code_now("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=60")
            .expect("valid otpauth uri");
    assert_eq!(current.period, 60);
    assert!(current.seconds_remaining >= 1 && current.seconds_remaining <= 60);
}

#[test]
fn a_zero_period_cannot_reach_the_cycle_arithmetic() {
    // `period=0` would divide by zero in `code_now`; the parser clamps it to a
    // one-second cycle instead of trusting the URI.
    let current =
        totp::code_now("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&period=0")
            .expect("a zero period must still produce a code");
    assert_eq!(current.period, 1);
    assert_eq!(current.code.len(), 6);
}

#[test]
fn digits_are_clamped_to_a_usable_range() {
    let current =
        totp::code_now("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=0")
            .expect("zero digits must still produce a code");
    assert_eq!(current.code.len(), 1, "digits are clamped to at least 1");
}
