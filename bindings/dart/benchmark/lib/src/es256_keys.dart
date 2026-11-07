/// A P-256 key pair made for this benchmark only, never used elsewhere.
const es256PrivatePem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/8tcvjmfRcrYaznt
6deefM20VRH49+DGO/FDYRlIB6OhRANCAAQ3QMa3jpf7GKQ31X015Yjbe3sXRSS6
q0jlyVh1EyFOOe+1Y/8a4bzHVBQUeeo4Lr4gvekmJJtNqUwbLgWzgJUq
-----END PRIVATE KEY-----''';

/// The public half of [es256PrivatePem].
const es256PublicPem = '''
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN0DGt46X+xikN9V9NeWI23t7F0Uk
uqtI5clYdRMhTjnvtWP/GuG8x1QUFHnqOC6+IL3pJiSbTalMGy4Fs4CVKg==
-----END PUBLIC KEY-----''';
