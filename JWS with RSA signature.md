This example is taken from **com.nimbusds.jose.crypto.RSASSATest**.

It demonstrates how to create, sign and verify JSON Web Signature (JWS) objects protected by means of an RSA signature ([RFC 3447](http://www.ietf.org/rfc/rfc3447.txt)). In this case the payload is a simple string but can also be a JSON string or a BASE64 encoded binary blob.

The public key can be communicated through the "jku" or "jwk" header parameters, or through some other mean before the JWS object is communicated.

    // RSA signatures require a public and private RSA key pair,
    // the public key must be made known to the JWS recipient in
    // order to verify the signatures
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    keyGenerator.initialize(1024);
    
    KeyPair kp = keyGenerator.genKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

    // Create RSA-signer with the private key
    JWSSigner signer = new RSASSASigner(privateKey);

    // Prepare JWS object with simple string as payload
    JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("In RSA we trust!"));

    // Compute the RSA signature
    jwsObject.sign(signer);

    assertTrue(jwsObject.getState().equals(JWSObject.State.SIGNED));

    // To serialize to compact form, produces something like
    // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
    // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
    // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
    // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
    String s = jwsObject.serialize();

    // To parse the JWS and verify it, e.g. on client-side
    jwsObject = JWSObject.parse(s);

    JWSVerifier verifier = new RSASSAVerifier(publicKey);

    assertTrue(jwsObject.verify(verifier));

    assertEquals("In RSA we trust!", jwsObject.getPayload().toString());