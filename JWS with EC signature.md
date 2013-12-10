This example is taken from **com.nimbusds.jose.crypto.**ECDSARoundTripTest.

It demonstrates how to create, sign and verify JSON Web Signature (JWS) objects protected by means of an Elliptic Curve (EC) signature (RFC 3447). In this case the payload is a simple string but can also be a JSON string or a BASE64 encoded binary blob.

The employed EC keys should be of sufficient length to match the required protection. Note that while EC signatures are shorter than an RSA signature, they take significantly longer to compute. 

The Nimbus JOSE+JWT library supports all standard EC digital signature algorithms. They have the following JWS algorithm identifiers:

    JWSAlgorithm.ES256 - EC DSA with SHA-256
    JWSAlgorithm.ES384 - EC DSA with SHA-384
    JWSAlgorithm.ES512 - EC DSA with SHA-512


The public key can be communicated through the "jwk", "jku", "x5u" and/or "x5c" JWS header parameters, or through some other mean before the JWS object is communicated.

    // Create the public and private EC keys
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
    keyGenerator.initialize(new ECParameterSpec(/*...*/));
    KeyPair keyPair = keyGenerator.generateKeyPair();

    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

    // Create the EC signer
    JWSSigner signer = new ECDSASigner(privateKey.getS());

    // Creates the JWS object with payload
    JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload("Elliptic cure"));

    // Compute the EC signature
    jwsObject.sign(signer);

    assertEquals(JWSObject.State.SIGNED, jwsObject.getState());

    // Serialize the JWS to compact form
    String s = jwsObject.serialize();


    // The recipient must create a verifier with the public 'x' and 'y' EC params
    BigInteger x = publicKey.getW().getAffineX();
    BigInteger y = publicKey.getW().getAffineY();
    JWSVerifier verifier = new ECDSAVerifier(x, y);
    
     // Verify the EC signature
    assertTrue("EC256 signature verified", jwsObject.verify(verifier));
    assertEquals("Elliptic cure", jwsObject.getPayload().toString());