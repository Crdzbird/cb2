# cb2 JVM benchmarks

JMH benchmarks of the cb2 Java library against JJWT, Nimbus JOSE+JWT and
paseto4j, on one claims payload (iss, sub, aud, exp, iat, jti and a
custom role claim). Each benchmark issues a token, or checks one and its
claims (issuer, audience and expiry) on the way back. This project is
never published; the JWT and PASETO libraries stay here.

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
