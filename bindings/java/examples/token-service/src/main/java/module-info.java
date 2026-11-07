/** The token service example: issues cb2 tokens over HTTP and checks holder-bound requests. */
@SuppressWarnings("module")
module com.cipherbird.cb2.example.service {
    requires com.cipherbird.cb2;
    requires java.net.http;
    requires jdk.httpserver;
}
