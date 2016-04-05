# Java Implementation of ITS Intelligent Transport Systems (ITS) Security Security header and certificate formats
# ETSI TS 103 097 V1.2.1 and IEEE 1609.2 2015

This is a library used to generate data structures from the ETSI TS 103 097 (EU) and IEEE 1609.2 2015 (US) specification.

# License
The software is released under AGPL, see LICENSE.txt for more details. In order to get the software under a different licensing agreement please contact p.vendil (at) cgi.com

# What's new in 0.9.8

- Added support for ETSI TS 103 097 V1.2.1 (Version 2 certificate and SecureMessages), V2 Certificates and SecureMessages have been interoperability tested 
with ETSI test tool from ts_10309603v010201p0 package. (Tests was done to verify generated messages and generation and parsing of certificates). 
- Added utility methods to retrieve java.security variant of verification public key from certificates (common API for both US and EU standard)


# What's New in 0.9.7

- Added support for IEEE 1609.2 certificate (US standard)

# What's New in 0.9.6

- Improved automatic build of project.

# What's New in 0.9.5

- Interoperability testing of all aspects except encryption.
- Bug-fixes on signature generation where trailer field signature type wasn't included in the digest calculation.

# What's New in 0.9.0

- Ecies Encryption scheme support in DefaultCryptoManager
- Restructured the behaviour of CryptoManager verifySecuredMessage to throw InvalidITSSignatureException instead of returning a boolean


# EU Standard ETSI TS 103 097 V1.1.1

It supports generation of the following data structures will all related substructures:

- Root CA Certificate
- Enrollment CA Certificate
- Authorization CA Certificate
- Enrollment Credential Certificate
- Authorization Ticket
- Secure Messages for CAM and DENM

Encryption of generated Secure Messages is not implemented in the current version. 

See Javadoc and examples below for more detailed information.

Version 0.9.5 and above have been inter-operability tested with the site https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/
and all version 1 Certificate and signed SecuredMessages v1 is successfully verified.

_Important_: Encryped Secured Messages are still not fully inter-operability tested and might contain problems.

## Example Code 

Full example code can be seen in src/test/java/org/certificateservices/custom/c2x/demo it contains demo of both ITS (EU) and IEEE (US) standards.

Before doing anything else you need to initialize a CryptoManager used for all cryptographic operations.

```

    	//Create a crypto manager in charge of communicating with underlying cryptographic components
	    CryptoManager cryptoManager = new DefaultCryptoManager();	
	    // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
	    cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
```

### Root CA
Example code on how to generate Root a CA, use the AuthorityCertGenerator:

```

	    // Create an authority certificate generator and initialize it with the crypto manager. 
	    // This constructor creates a Version 2 generator, use alternate constructor where certificate version can be specified for version 1.
	    AuthorityCertGenerator authorityCertGenerator = new AuthorityCertGenerator(cryptoManager);
	    
	    // Generate a reference to the Root CA Signing Keys	    
	    KeyPair rootCASigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Root CA
	    List<BigInteger> rootCAItsAidList = new ArrayList<BigInteger>();
	    rootCAItsAidList.add(new BigInteger("1"));
	    
	    // Generate the root CA Certificate, without any encryption keys or geographic region.
	    Certificate rootCACertificate = authorityCertGenerator.genRootCA("TestRootCA".getBytes("UTF-8"), // subjectName
	    		rootCAItsAidList, //itsAidList 
	    		4, // assuranceLevel 
                3, // confidenceLevel 
	    		new Date(), // validFrom 
                new Date(System.currentTimeMillis() + 1000 * 3600* 24 * 365 * 10), // validTo, 10 years in this example 
	    		null, // geographicRegion
	    		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, // signingPublicKeyAlgorithm 
	    		rootCASigningKeys.getPublic(), // signPublicKey,
	    		rootCASigningKeys.getPrivate(), // signPrivateKey,
                null, // encPublicKeyAlgorithm
                null); // encPublicKey

```

### Enrollment CA
To generate an Enrollment CA:

```

	    // Generate a reference to the Enrollment CA Signing Keys	    
	    KeyPair enrollmentCASigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Enrollment CA
	    List<BigInteger> enrollmentCAItsAidList = new ArrayList<BigInteger>();
	    enrollmentCAItsAidList.add(new BigInteger("2"));

	    // Generate a reference to the Enrollment CA Signing Keys
	    Certificate enrollmentCACertificate =authorityCertGenerator.genEnrollmentAuthorityCA(
	    		"TestEnrollmentCA".getBytes("UTF-8"),//subjectName 
	    		enrollmentCAItsAidList, //itsAidList 
	    		4, //assuranceLevel 
	    		3, //confidenceLevel 
	    		new Date(), // validFrom 
                new Date(System.currentTimeMillis() + 1000 * 3600* 24 * 365 * 10), // validTo, 10 years in this example 
	    		null, // geographicRegion
	    		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, // signingPublicKeyAlgorithm 
	    		enrollmentCASigningKeys.getPublic(), 
                null, // encPublicKeyAlgorithm
                null, // encPublicKey
	    		rootCASigningKeys.getPrivate(), 
	    		rootCACertificate);

```

## Authority CA
To generate an Authority CA:

```

	    // Generate a reference to the Authorization CA Signing Keys	    
	    KeyPair authorityCASigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Authorization CA
	    List<BigInteger> authorityCAItsAidList = new ArrayList<BigInteger>();
	    authorityCAItsAidList.add(new BigInteger(""+SecuredMessageGenerator.ITS_AID_CAM));
	    authorityCAItsAidList.add(new BigInteger(""+SecuredMessageGenerator.ITS_AID_DENM));

	    // Generate a reference to the Authorization CA Signing Keys
	    Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationAuthorityCA(
	    		"TestAuthorizationCA".getBytes("UTF-8"),//subjectName 
	    		enrollmentCAItsAidList, //itsAidList 
	    		4, //assuranceLevel 
	    		3, //confidenceLevel 
	    		new Date(), // validFrom 
                new Date(System.currentTimeMillis() + 1000 * 3600* 24 * 365 * 10), // validTo, 10 years in this example 
	    		null, // geographicRegion
	    		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, // signingPublicKeyAlgorithm 
	    		authorityCASigningKeys.getPublic(), 
                null, // encPublicKeyAlgorithm
                null, // encPublicKey
	    		rootCASigningKeys.getPrivate(), 
	    		rootCACertificate);

```

### Enrollment Credential

To create an Enrollment Credential use the EnrollmentCredentialCertGenerator.

```

	    // Now we have the CA hierarchy, the next step is to generate an enrollment credential
	    // First we create a Enrollment Credential Cert Generator using the newly created Enrollment CA.
	    // This constructor creates a Version 2 generator, use alternate constructor where certificate version can be specified for version 1.
	    EnrollmentCredentialCertGenerator enrollmentCredentialCertGenerator = new EnrollmentCredentialCertGenerator(cryptoManager, enrollmentCACertificate, enrollmentCASigningKeys.getPrivate());
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialSigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialEncryptionKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);

	    // Generate the list of ITS AID values for the enrollment credential
	    List<BigInteger> enrollCredItsAidList = new ArrayList<BigInteger>();
	    enrollCredItsAidList.add(new BigInteger("4"));
	    // Then use the following command to generate a enrollment credential
	    Certificate enrollmentCredential = enrollmentCredentialCertGenerator.genEnrollmentCredential(
	    		SignerInfoType.certificate_digest_with_ecdsap256,//signerInfoType 
	    		"TestEnrollmentCredential".getBytes("UTF-8"),// subjectName 
	    		enrollCredItsAidList,// itsAidList 
	    		4,// assuranceLevel 
	    		3,// confidenceLevel 
	    		new Date(), // validFrom 
                new Date(System.currentTimeMillis() + 1000 * 3600* 24 * 365 * 10), // validTo, 10 years in this example 
	    		null,// geographicRegion 
	    		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,// signingPublicKeyAlgorithm 
	    		enrollmentCredentialSigningKeys.getPublic(),// signPublicKey 
	    		PublicKeyAlgorithm.ecies_nistp256,// encPublicKeyAlgorithm 
	    		enrollmentCredentialEncryptionKeys.getPublic() // encPublicKey
	    		);
	    		
```

### Authorization Ticket 
To create an Authorization Ticket l use the AuthorizationTicketCertGenerator.

```

	    // Authorization Tickets are created by the AuthorizationTicketCertGenerator
	    // This constructor creates a Version 2 generator, use alternate constructor where certificate version can be specified for version 1.
	    AuthorizationTicketCertGenerator authorizationTicketCertGenerator = new AuthorizationTicketCertGenerator(cryptoManager, authorityCACertificate, authorityCASigningKeys.getPrivate());
	    
	    // Next we generate keys for an authorization ticket.
	    KeyPair authorizationTicketSigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Next we generate keys for an authorization ticket.
	    KeyPair authorizationTicketEncryptionKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Authorization Ticket
	    List<BigInteger> authTicketItsAidList = new ArrayList<BigInteger>();
	    authTicketItsAidList.add(new BigInteger("4"));
	    
	    Certificate authorizationTicket = authorizationTicketCertGenerator.genAuthorizationTicket(
	    		SignerInfoType.certificate_digest_with_ecdsap256,//signerInfoType 
	    		enrollCredItsAidList,// itsAidList 
	    		4,// assuranceLevel 
	    		3,// confidenceLevel 
	    		new Date(), // validFrom 
                new Date(System.currentTimeMillis() + 1000 * 3600* 24 * 365 * 10), // validTo, 10 years in this example 
	    		null,// geographicRegion 
	    		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,// signingPublicKeyAlgorithm 
	    		authorizationTicketSigningKeys.getPublic(),// signPublicKey 
	    		PublicKeyAlgorithm.ecies_nistp256,// encPublicKeyAlgorithm 
	    		authorizationTicketEncryptionKeys.getPublic()); // encPublicKey
```

### Secured Messages

To create Secured Messages use the SecuredMessageGenerator.

```

	    // Secure Messages are created by the Secure Message Generator
	    // This constructor creates a Version 2 generator, use alternate constructor where certificate version can be specified for version 1.
	    SecuredMessageGenerator securedMessageGenerator = new SecuredMessageGenerator(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicket, new Certificate[]{},authorityCASigningKeys.getPrivate(), PublicKeyAlgorithm.ecies_nistp256, authorizationTicketEncryptionKeys.getPrivate());
	    
	    // Next to generate a CAM Message, supported SignerIntoTypes are certificate_digest_with_ecdsap256 and certificate
	    SecuredMessage signedCAMMessage = securedMessageGenerator.genSignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, "SomeMessageData".getBytes("UTF-8"));
	    
	    byte[] someHash = {0x01,0x02,0x03};
	   // To Generate a CAM Unreqognized certificates message
	    List<HashedId3> unrecognizedCertificates = new ArrayList<HashedId3>();
	    unrecognizedCertificates.add(new HashedId3(someHash));	    
		SecuredMessage unReqognizedMessages= securedMessageGenerator.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate, unrecognizedCertificates);
		
		// To Generate a DENM Message
		ThreeDLocation generationLocation = new ThreeDLocation(900000000, 1800000000 , 100);
		SecuredMessage signedDENMMessage = securedMessageGenerator.genSignedDENMMessage(generationLocation, "SomeMessageData".getBytes("UTF-8"));
```

### Encrypted Secured Messages
Neither CAM nor DENM messages should be encrypted, so in this example is a SecureMessage built manually

```

		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,new Time64(Certificate.CERTIFICATE_VERSION_2,new Date()))); // generate generation time
		headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,generationLocation));
        headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,new IntX(123))); // Just have any value since no known message type uses encryption
        
		// The payload that should be encrypted should have type encrypted, others will be ignored.
		Payload  payload = new Payload(PayloadType.encrypted,"SomeClearText".getBytes("UTF-8"));
		
		SecuredMessage secureMessage = new SecuredMessage(headerFields, payload);
		
		// First we create a list of receipients certificates that should be able to decrypt the payload.
		List<Certificate> receipients = new ArrayList<Certificate>();
		receipients.add(authorizationTicket);
		
		// Then we use the cryptoManager to create a cloned message with encrypted payload.
		SecuredMessage encryptedMessage = cryptoManager.encryptSecureMessage(secureMessage, PublicKeyAlgorithm.ecies_nistp256, receipients);
		
		// Verify that the payload data have been replaced with it's encrypted content.
		assert !(new String(encryptedMessage.getPayloadFields().get(0).getData(), "UTF-8").equals("SomeClearText"));
		
		// To decrypt we need the receivers certificate and the related private key.
		SecuredMessage decryptedMessage = cryptoManager.decryptSecureMessage(encryptedMessage, authorizationTicket, authorizationTicketEncryptionKeys.getPrivate());
		
		// Verify that the payload is in clear text again. 
		assert new String(decryptedMessage.getPayloadFields().get(0).getData(), "UTF-8").equals("SomeClearText");
		
```

### Encrypted And Signed Secured Messages
In this example we generate messages with payload type signed_and_encrypted, i.e the data is both signed and encrypted.

```

		// We start with constructing a secured message
		headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,new Time64(Certificate.CERTIFICATE_VERSION_2,new Date()))); // generate generation time
		headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,generationLocation));
        headerFields.add(new HeaderField(SecuredMessage.PROTOCOL_VERSION_2,new IntX(123))); // ITS_AID, Just have any value since no known message type uses encryption
        
        // There is no need to add recipient_info or encryption_parameters, these will be calculated and appended automatically by the crypto manager.
		// The payload that should be encrypted should have type encrypted, others will be ignored.
		payload = new Payload(PayloadType.signed_and_encrypted,"SomeClearText".getBytes("UTF-8"));
		
		secureMessage = new SecuredMessage(headerFields, payload);
		
		SecuredMessage encryptedAndSignedMessage = cryptoManager.encryptAndSignSecureMessage(secureMessage, enrollmentCredential, new Certificate[]{enrollmentCACertificate},
				SignerInfoType.certificate, 
				PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, 
				enrollmentCredentialSigningKeys.getPrivate(), 
				PublicKeyAlgorithm.ecies_nistp256, receipients);
		
		
		assert encryptedAndSignedMessage.getTrailerFields().get(0).getTrailerFieldType() == TrailerFieldType.signature;
		// Verify that the payload data have been replaced with it's encrypted content.
		assert !(new String(encryptedAndSignedMessage.getPayloadFields().get(0).getData(), "UTF-8").equals("SomeClearText"));
		
		// To verify and decrypt the message use the following method, if signer info type is certificate_digest_with_ecdsap256, you need to verify with
		// alternative method where signer certificate is specified.
		SecuredMessage decryptedAndVerifiedMessage = cryptoManager.verifyAndDecryptSecuredMessage(encryptedAndSignedMessage, authorizationTicket, authorizationTicketEncryptionKeys.getPrivate());
		assert new String(decryptedAndVerifiedMessage.getPayloadFields().get(0).getData(), "UTF-8").equals("SomeClearText");

```

### To Encode and Decode Certificates and Secured Messages

```

		// To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationTicket.getEncoded();
	    
	    // To decode certificate data use the following constructor
	    Certificate decodedCertificate = new Certificate(certificateData);
	    
	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedDENMMessage.getEncoded();
	    
	    // To decode message data use the following constructor.
	    SecuredMessage decodedMessage = new SecuredMessage(messageData);
```

### HashedXId Example 

```

	    // To calculate correct Certificate HashedId3 or 8 use the constructor supplying the certificate and cryptomanager to automatically normalize the certificate before calculating
	    // the hash value.
	    HashedId8 certHash = new HashedId8(authorizationTicket, cryptoManager);
	    
	    // The certificate hash value can be extracted with.
	    certHash.getHashedId();

```



# US Standard IEEE 1609.2

The implementation supports the following:

- Encodes using ASN.1 COER
- Support for both ecdsaNistP256 and ecdsaBrainpoolP256r1 algorithm schemes 
- Generation of RootCA, Enrollment CA (Long Term) and Authorization (Short Term) CA
- Generation of Enrollment Certificates and Authorization Certificate
- Support for both explicit and implicit certificate generation
- Support signing and encryption of SecuredData structures
- Generation of SecuredCRL structures.

_Important_: The encryption scheme hasn't been properly tested for inter-operability yet and might contain wrong ECIES parameters.

## Example Code 

Full example code can be seen in src/test/java/org/certificateservices/custom/c2x/demo it contains demo of both ITS (EU) and IEEE (US) standards.

Before doing anything else you need to initialize a CryptoManager used for all cryptographic operations.

```

    	//Create a crypto manager in charge of communicating with underlying cryptographic components
	    CryptoManager cryptoManager = new DefaultCryptoManager();	
	    // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
	    cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	    
```

### Root CA

Example code on how to generate Root a CA, use the AuthorityCertGenerator:

```

        // Create an authority certificate generator and initialize it with the crypto manager. 
	    AuthorityCertGenerator authorityCertGenerator = new AuthorityCertGenerator(cryptoManager);
	    
	    // Generate a reference to the Root CA Keys	    
	    KeyPair rootCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair rootCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    CertificateId rootCAId = new CertificateId(new Hostname("Test RootCA"));
	    ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);
	    List<Integer> countries = new ArrayList<Integer>();
	    countries.add(SWEDEN);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);
		
	    // Generate the root CA Certificate, without any encryption keys or geographic region.
	    Certificate rootCACertificate = authorityCertGenerator.genRootCA(rootCAId, // CertificateId
	    		rootCAValidityPeriod, //ValidityPeriod
	    		region, //GeographicRegion
	    		4, // assuranceLevel 
                3, // confidenceLevel 
                3, // minChainDepth
                -1, // chainDepthRange
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		rootCASigningKeys.getPublic(), // signPublicKey
	    		rootCASigningKeys.getPrivate(), // signPrivateKey
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
	    		rootCAEncryptionKeys.getPublic()); // encPublicKey
	    		
```

### Enrollment CA (Long Term)

To generate an Enrollment CA:

```

	    // Generate a reference to the Enrollment CA Keys	    
	    KeyPair enrollmentCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    CertificateId enrollmentCAId = new CertificateId(new Hostname("Test Enrollment CA"));
	    ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 37);
	    
		byte[] cracaid = Hex.decode("010203"); // Some cracaid
		PsidSspRange[] subjectPerms = new PsidSspRange[1];
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null)); // Insert proper subject permissions here.
	    // Generate a reference to the Enrollment CA Signing Keys
	    Certificate enrollmentCACertificate =authorityCertGenerator.genLongTermEnrollmentCA(
	    		CertificateType.explicit, // Implicit or Explicit certificate
	    		enrollmentCAId,// CertificateId
				enrollmentCAValidityPeriod, 
				region,  //GeographicRegion
				subjectPerms,
				cracaid,
				99, // CrlSeries
	    		4, // assuranceLevel 
                3, // confidenceLevel 
                2, // minChainDepth
                0, // chainDepthRange
                SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                enrollmentCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
				rootCACertificate, // signerCertificate
				rootCASigningKeys.getPublic(), // signCertificatePublicKey, must be specified separately to support implicit certificates.
				rootCASigningKeys.getPrivate(),
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
	    		enrollmentCAEncryptionKeys.getPublic() // encryption public key
	    		);
	    		
```

### Authorization CA (Short Term)

To generate an Authorization CA:

```

	    // Generate a reference to the Authorization CA Keys	    
	    KeyPair authorityCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair authorityCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    CertificateId authorityCAId = new CertificateId(new Hostname("Test Enrollment CA"));
	    ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 15);
	    
		cracaid = Hex.decode("040506"); // Some cracaid
		subjectPerms = new PsidSspRange[1];
		subjectPerms[0] = new PsidSspRange(new Psid(6), new SspRange(SspRangeChoices.all, null)); // Insert proper subject permissions here.

	    // Generate a reference to the Authorization CA Signing Keys
	    Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
	    		CertificateType.explicit, // Implicit or Explicit certificate
	    		authorityCAId,// CertificateId
	    		authorityCAValidityPeriod, 
				region,  //GeographicRegion
				subjectPerms,
				cracaid,
				99, // Some CrlSeries
	    		4, // assuranceLevel 
                3, // confidenceLevel 
                2, // minChainDepth
                0, // chainDepthRange
                SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                authorityCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
				rootCACertificate, // signerCertificate
				rootCASigningKeys.getPublic(), // signCertificatePublicKey,
				rootCASigningKeys.getPrivate(),
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
	    		authorityCAEncryptionKeys.getPublic() // encryption public key
	    		);
	    		
```


### Enrollment Certificate

To create an Enrollment Certificate (explicit in this example) use the EnrollmentCertGenerator.

```

	    // First we create a Enrollment Credential Cert Generator using the newly created Enrollment CA.
	    EnrollmentCertGenerator enrollmentCredentialCertGenerator = new EnrollmentCertGenerator(cryptoManager);
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

	    CertificateId enrollCertId = new CertificateId(Hex.decode("0102030405060708"));
	    ValidityPeriod enrollCertValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);
	    
		PsidSspRange[] certRequestPermissions = new PsidSspRange[1];
		certRequestPermissions[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null)); // Insert proper subject permissions here.
	    
	    // Then use the following command to generate a enrollment credential
	    Certificate enrollmentCredential = enrollmentCredentialCertGenerator.genEnrollCert(
	    		CertificateType.explicit, // Implicit or Explicit certificate
	    		enrollCertId, // Certificate Id,
	    		enrollCertValidityPeriod, 
	    		region, 
	    		certRequestPermissions, 
	    		cracaid, // insert proper cracaid here.
	    		99, // Some CrlSeries
	    		4, 
	    		3, 
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		enrollmentCredentialSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
	    		enrollmentCACertificate, // signerCertificate
	    		enrollmentCASigningKeys.getPublic(), // signCertificatePublicKey,
	    		enrollmentCASigningKeys.getPrivate(), 
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm 
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
	    		enrollmentCredentialEncryptionKeys.getPublic() // encryption public key
	    		);
	    		
```

### Authorization Certificate (With implicit certificate)

To create an Authorization Certificate (implicit in this example) use the AuthorizationCertGenerator.

```

	    // Authorization certificates are created by the AuthorizationCertGenerator
	    AuthorizationCertGenerator authorizationCertGenerator = new AuthorizationCertGenerator(cryptoManager);
	    
	    // Next we generate keys for an authorization certificate.
	    KeyPair authorizationCertRequestSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    // Next we generate keys for an authorization certificate.
	    KeyPair authorizationCertEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    CertificateId authorizationCertId = new CertificateId(Hex.decode("9999999999"));
	    ValidityPeriod authorizationCertValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);
	    
	    
		PsidSsp[] appPermissions = new PsidSsp[1];
		appPermissions[0] = new PsidSsp(new Psid(6), null); // Insert proper app permissions here.
	    
	    // Generate a certificate as an implicit certificate.
	    Certificate authorizationCert = authorizationCertGenerator.genAuthorizationCert(
	    		CertificateType.implicit, // Implicit or Explicit certificate
	    		authorizationCertId, // Certificate Id,
	    		authorizationCertValidityPeriod, 
	    		region, 
	    		appPermissions, 
	    		cracaid, // insert proper cracaid here.
	    		99, // Some CrlSeries
	    		4, 
	    		3, 
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		authorizationCertRequestSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
	    		authorityCACertificate, // signerCertificate
	    		authorityCASigningKeys.getPublic(), // signCertificatePublicKey,
	    		authorityCASigningKeys.getPrivate(), 
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm 
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
	    		authorizationCertEncryptionKeys.getPublic() // encryption public key
	    		); 
	    
	    // Implicit certificate needs to have it's private key reconstructed. R is given inside the ImplicitCertificateData (which is the actual type of implicit certificates)
	    PrivateKey authorizationCertSigningPrivateKey = cryptoManager.reconstructImplicitPrivateKey(authorizationCert, 
	    		((ImplicitCertificateData) authorizationCert).getR(), 
	    		SignatureChoices.ecdsaNistP256Signature, 
	    		authorizationCertRequestSigningKeys.getPrivate(), authorityCASigningKeys.getPublic(),
	    		authorityCACertificate);
	    		
```

### Certificate Encoding and Decoding Example 

To encode and decode a certificate use:
		
```

	    // To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationCert.getEncoded();
	    
	    // To decode certificate data use the following constructor
	    Certificate decodedCertificate = new Certificate(certificateData);

```

### Secured Data Example

To generate signed and/or encrypted Secured Data use the SecuredMessageGenerator:

```

	    // Secure Messages are created by the Secure Message Generator
	    SecuredDataGenerator securedMessageGenerator = new SecuredDataGenerator(SecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature);
	    
	    // It is then possible to create a signed message with the following code
	      // First generate a Header with
	    HeaderInfo hi = securedMessageGenerator.genHeaderInfo(
	    		123L, // psid Required, 
	    		null, // generationTime Optional
	    		null, // expiryTime Optional
	    		null, // generationLocation Optional
	    		null, // p2pcdLearningRequest Optional
	    		null, // cracaid Optional
	    		null, // crlSeries Optional 
	    		null, // encType Type of encryption when encrypting a message with a encryption key references in a signed message instead of a certificate. Optional
	    		null // encryptionKey Optional
	    		);
	    
	    // This method can be used to sign the data
	    Ieee1609Dot2Data signedData = securedMessageGenerator.genSignedData(hi, 
	    		"TestData".getBytes(), // The actual payload message to sign. 
	    		SignerIdentifierType.HASH_ONLY, // One of  HASH_ONLY, SIGNER_CERTIFICATE, CERT_CHAIN indicating reference data of the signer to include in the message
	    		new Certificate[] {authorizationCert,authorityCACertificate, rootCACertificate}, // The chain is required even though it isn't included in
	    		  // the message if eventual implicit certificates need to have it's public key reconstructed.
	    		authorizationCertSigningPrivateKey); // Signing Key
	    
	    // The message can be encrypted with the method
	      // First construct a list of recipient which have the public key specified either as a symmetric key, certificate or in header of signed data
	      // In this example we will use certificate as reciever, see package org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient for more details.
	    Ieee1609Dot2Data encryptedData = securedMessageGenerator.encryptData(BasePublicEncryptionKeyChoices.ecdsaNistP256, 
	    		  signedData.getEncoded(), new Recipient[] {new CertificateRecipient(enrollmentCredential)});
	      // It is also possible to encrypt using a pre shared key using the encryptDataWithPresharedKey() method.
	    
	    // It is also possible to sign and encrypt in one go.
	    byte[] encryptedAndSignedMessage = securedMessageGenerator.signAndEncryptData(hi, 
	    		"TestData2".getBytes(), 
	    		SignerIdentifierType.HASH_ONLY, 
	    		new Certificate[] {authorizationCert,authorityCACertificate, rootCACertificate}, 
	    		authorizationCertSigningPrivateKey, // Important to use the reconstructed private key for implicit certificates
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, 
	    		new Recipient[] {new CertificateRecipient(enrollmentCredential)});
	    
	    // To decrypt and verify a signed message it is possible to use the following
	      // First build a truststore of trust anchors (root CA certificate or equivalent)
	    Map<HashedId8, Certificate> trustStore = securedMessageGenerator.buildCertStore(new Certificate[] {rootCACertificate});
	      // Second build a store of known certificate that might be referenced in the message.
	    Map<HashedId8, Certificate> certStore = securedMessageGenerator.buildCertStore(new Certificate[] {authorizationCert, authorityCACertificate});
	      // To decrypt build a reciever store of known decryption keys and related receiver info, this can be certificate, signed message containing encryption key
	      // in header, symmetric key or pre shared key.
	    Map<HashedId8, Receiver> recieverStore = securedMessageGenerator.buildRecieverStore(new Receiver[] { new CertificateReciever(enrollmentCredentialEncryptionKeys.getPrivate(), enrollmentCredential)});
		  // Finally perform the decryption with.
	    byte[] decryptedMessage = securedMessageGenerator.decryptAndVerifySignedData(encryptedAndSignedMessage, 
	    		certStore, 
	    		trustStore,
	    		recieverStore, 
	    		true, //requiredSignature true if message must be signed otherwise a IllegalArgument is throwm
	    		true //requireEncryption true if message must be encrypted otherwise a IllegalArgument is throwm
	    		);
	      // It is also possilbe to use the methods decryptData or verifySignedData (or verifyReferencedSignedData) for alternative methods to verify and decrypt messages.
	    

```

### Secured Data Encoding and Decoding Example 


To encode and decode a secured data use:
		
```

	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedData.getEncoded();
	    
	    // To decode message data use the following constructor.
	    Ieee1609Dot2Data decodedMessage = new Ieee1609Dot2Data(messageData);

```