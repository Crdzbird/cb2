# cb2 JVM benchmarks

JMH benchmarks of the cb2 Java library against JJWT, Nimbus JOSE+JWT and
paseto4j, on one claims payload (iss, sub, aud, exp, iat, jti and a
custom role claim). Each benchmark issues a token, or checks one and its
claims (issuer, audience and expiry) on the way back. This project is
never published; the JWT and PASETO libraries stay here.

`Cb2Bench` also measures the experimental compact forms, cb3.local and
cb3.public (`compactLocalSeal`, `compactLocalOpen`, `compactPublicSign`,
`compactPublicVerify`), and the same four under a claim table of the
issuer and the audience (`tabledLocalSeal`, `tabledLocalOpen`,
`tabledPublicSign`, `tabledPublicVerify`), on the same claims; their
timings are not yet in the table of the main README.

Run every benchmark (about six minutes: 2 forks, 3 warmup and 5 measured
iterations of one second each, average time per operation in
microseconds):

    ./gradlew :bench:run

Pass JMH options through `--args`, for instance one class with JSON
output:

    ./gradlew :bench:run --args="Cb2Bench -rf json -rff cb2.json"

Print the size of each token:

    ./gradlew :bench:tokenSizes

The results and the machine they were measured on are in the
Benchmarks section of [../README.md](../README.md).
