This example is taken from **com.nimbusds.jose.crypto.MACTest**.

It demonstrates how to create and verify JSON Web Signature (JWS) protected objects. In this case the payload is a simple "Hello, world!" string but can also be a JSON string or a BASE64 encoded binary array.

Note that MAC protection requires producer and recipient to posses a shared secret, negotiated through some out-of-band mechanism before the JWS object is communicated.


    // Generate random 32-bit shared secret
    SecureRandom random = new SecureRandom();
    byte[] sharedSecret = new byte[32];
    random.nextBytes(sharedSecret);

    // Create HMAC signer
    JWSSigner signer = new MACSigner(sharedSecret);

    // Prepare JWS object with "Hello, world!" payload
    JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"));

    // Apply the HMAC
    jwsObject.sign(signer);

    assertTrue(jwsObject.getState().equals(JWSObject.State.SIGNED));

    // To serialize to compact form, produces something like
    // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
    String s = jwsObject.serialize();

    // To parse the JWS and verify it, e.g. on client-side
    jwsObject = JWSObject.parse(s);

    JWSVerifier verifier = new MACVerifier(sharedSecret);

    assertTrue(jwsObject.verify(verifier));

    assertEquals("Hello, world!", jwsObject.getPayload().toString());
