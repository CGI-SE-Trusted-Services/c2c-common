# Java Implementation of ITS Intelligent Transport Systems (ITS) Security Security header and certificate formats
# ETSI TS 103 097 V1.3.1 and IEEE 1609.2a 2017

This is a library used to generate data structures from the ETSI TS 103 097 1.3.1 (EU) and IEEE 1609.2 2016 (With 1609.2a 2017 Amendment) (US) specification.

# License
The software is released under AGPL, see LICENSE.txt for more details. In order to get the software under a different licensing agreement please contact p.vendil (at) cgi.com

# What's new in 2.0.0-Beta1

- Updated IEEE 1609.2 support to 2016 with 1609.2a 2017 amendment.
- Added support to generate new ITS ETSI TS 103 097 V1.3.1 structures based on 1609.2a 2017 
- Added test vector test of cryptographic algorithms from IEEE 1609.2a 2017
- Removed old ITS ETSI TS 103 097 V1.2.1 code and generators
- Fixed problem with COERBoolean

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


# EU Standard ETSI TS 103 097 V1.3.1

It supports generation of the following data structures will all related substructures:

- Root CA Certificate
- Enrollment CA Certificate
- Authorization CA Certificate
- Enrollment Credential Certificate
- Authorization Ticket
- Trust List Manager Certificate
- Secure Messages (CAM and DENM) and others

Encryption of generated Secure Messages is not implemented in the current version. 

See Javadoc and examples below for more detailed information.

## Example Code 

Full example code can be seen in src/test/java/org/certificateservices/custom/c2x/demo it contains demo of both ETSI (EU) and IEEE (US) standards.

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
	    ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);
	    
	    // Generate a reference to the Root CA Keys	    
	    KeyPair rootCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair rootCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

	    ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);
	    List<Integer> countries = new ArrayList<Integer>();
	    countries.add(SWEDEN);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);
		
	    // Generate the root CA Certificate, without any encryption keys or geographic region.
	    EtsiTs103097Certificate rootCACertificate = authorityCertGenerator.genRootCA("testrootca.test.com", // caName
	    		rootCAValidityPeriod, //ValidityPeriod
	    		region, //GeographicRegion
                3, // minChainDepth
                -1, // chainDepthRange
				Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		rootCASigningKeys.getPublic(), // signPublicKey
	    		rootCASigningKeys.getPrivate(), // signPrivateKey
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
	    		rootCAEncryptionKeys.getPublic()); // encPublicKey
		// There also exists a more general root ca generation method giving more flexibility in parameters.

```

### Enrollment CA
To generate an Enrollment CA:

```

	    // Generate a reference to the Enrollment CA Keys	    
	    KeyPair enrollmentCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 37);

	    // Generate a reference to the Enrollment CA Signing Keys
		EtsiTs103097Certificate enrollmentCACertificate =authorityCertGenerator.genEnrollmentCA("testea.test.com", // CA Name
				enrollmentCAValidityPeriod, 
				region,  //GeographicRegion
				new SubjectAssurance(1,3), // subject assurance (optional)
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

## Authority CA
To generate an Authority CA:

```

	    // Generate a reference to the Authorization CA Keys	    
	    KeyPair authorityCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    KeyPair authorityCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 15);

	    // Generate a reference to the Authorization CA Signing Keys
		EtsiTs103097Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
				"testaa.test.com", // CA Name
	    		authorityCAValidityPeriod, 
				region,  //GeographicRegion
				new SubjectAssurance(1,3), // subject assurance (optional)
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

### Enrollment Credential

To create an Enrollment Credential use the EnrollmentCredentialCertGenerator.

```

	    // First we create a Enrollment Credential Cert Generator using the newly created Enrollment CA.
		ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    // Next we generate keys for an enrollment credential.
	    KeyPair enrollmentCredentialEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

	    ValidityPeriod enrollCertValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);

	    // Then use the following command to generate a enrollment credential
		EtsiTs103097Certificate enrollmentCredential = enrollmentCredentialCertGenerator.genEnrollCredential(
				"0102030405060708", // unique identifier name
	    		enrollCertValidityPeriod, 
	    		region,
	    		Hex.decode("01C0"), //SSP data set in SecuredCertificateRequestService appPermission, two byte, for example: 0x01C0
	    		3, // assuranceLevel
				7, // confidenceLevel
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		enrollmentCredentialSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
	    		enrollmentCACertificate, // signerCertificate
	    		enrollmentCASigningKeys.getPublic(), // signCertificatePublicKey,
	    		enrollmentCASigningKeys.getPrivate(), 
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm 
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
	    		enrollmentCredentialEncryptionKeys.getPublic() // encryption public key
	    		);

	    // There also exists a more general method with flexible app permissions.
	    		
```

### Authorization Ticket 
To create an Authorization Ticket l use the AuthorizationTicketCertGenerator.

```

	    // Authorization tickets are created by the ETSIAuthorizationTicketGenerator
		ETSIAuthorizationTicketGenerator authorizationCertGenerator = new ETSIAuthorizationTicketGenerator(cryptoManager);
	    
	    // Next we generate keys for an authorization certificate.
	    KeyPair authorizationTokenSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
	    
	    // Next we generate keys for an authorization certificate.
	    KeyPair authorizationTicketEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

	    ValidityPeriod authorizationCertValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);

		PsidSsp[] appPermissions = new PsidSsp[1];
		appPermissions[0] = new PsidSsp(new Psid(6), null); // Insert proper app permissions here.
	    
	    // Generate a certificate as an explicit certificate.
		EtsiTs103097Certificate authorizationCert = authorizationCertGenerator.genAuthorizationTicket(
	    		authorizationCertValidityPeriod, // Validity Period
	    		region, // region,
				new SubjectAssurance(1,3), // Subject Assurance, optional
	    		appPermissions,
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
				authorizationTokenSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
	    		authorityCACertificate, // signerCertificate
	    		authorityCASigningKeys.getPublic(), // signCertificatePublicKey,
	    		authorityCASigningKeys.getPrivate(), 
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm 
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
				authorizationTicketEncryptionKeys.getPublic() // encryption public key
	    		);
```

### Trust List Manager Certificate

To create a trust list manager certificate.

```

		// Generate a reference to the Root CA Keys
		KeyPair tlmSigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		KeyPair tlmEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);


		ValidityPeriod tlmValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);
		// Generate the root CA Certificate, without any encryption keys or geographic region.
		EtsiTs103097Certificate trustListManagerCertificate = authorityCertGenerator.genTrustListManagerCert(
				"testtlm.test.com", // name
				rootCAValidityPeriod, //ValidityPeriod
				region, //GeographicRegion, optional
				Hex.decode("01C8"), // cTLServiceSpecificPermissions, 2 octets
				SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
				rootCASigningKeys.getPublic(), // signPublicKey
				rootCASigningKeys.getPrivate() // signPrivateKey
				 );
		// There also exists a more general root ca generation method giving more flexibility in parameters.
```

### Secured Messages

To create Secured Messages such as CAM or DENM use the SecuredMessageGenerator.

```

	    	    // EtsiTs103097Data are created by the Secure Message Generator
        		ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature);
        
        		// To generate a Signed CA Message it is possible to use
        		List<HashedId3> hashedId3s = new ArrayList<HashedId3>();
        		hashedId3s.add(new HashedId3(cryptoManager.digest(rootCACertificate.getEncoded(),HashAlgorithm.sha256)));
        		hashedId3s.add(new HashedId3(cryptoManager.digest(enrollmentCACertificate.getEncoded(),HashAlgorithm.sha256)));
        		SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3(hashedId3s);
        
        		byte[] cAMessageData = Hex.decode("SomeCAMessage");
        		EtsiTs103097DataSigned cAMessage = securedMessageGenerator.genCAMessage(new Time64(new Date()), // generationTime
        				inlineP2pcdRequest, //  InlineP2pcdRequest (Required)
        				rootCACertificate, // requestedCertificate
        				cAMessageData, // inner opaque CA message data
        				SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE, // signerIdentifierType
        				authorizationCert, // signerCertificate
        				authorizationTokenSigningKeys.getPrivate()); // signerPrivateKey
        
        
        		// To generate a Signed DEN Message
        		byte[] dENMessageData = Hex.decode("SomeDENMessage");
        		EtsiTs103097DataSigned dENMessage = securedMessageGenerator.genDENMessage(
        				new Time64(new Date()), // generationTime
        				new ThreeDLocation(1,2,3), // generationLocation
        				dENMessageData, // inner opaque DEN message data
        				authorizationCert, // signerCertificate
        				authorizationTokenSigningKeys.getPrivate()); // signerPrivateKey
        
        		// The securedMessageGenerator also have methods to generate more general EtsiTs103097Data profiles such as
        		// EtsiTs103097DataSigned, EtsiTs103097DataSignedExternalPayload, EtsiTs103097DataEncrypted and
        		// EtsiTs103097DataSignedAndEncrypted.
        
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
        	    		null, // encryptionKey Optional
        				null, // inlineP2pcdRequest Optional
        		null // requestedCertificate Optional
        	    		);
        
        	    // This method can be used to sign the data
        		EtsiTs103097DataSigned signedData = securedMessageGenerator.genEtsiTs103097DataSigned(hi,
        	    		"TestData".getBytes(), // The actual payload message to sign.
        	    		SecuredDataGenerator.SignerIdentifierType.HASH_ONLY, // One of  HASH_ONLY, SIGNER_CERTIFICATE, CERT_CHAIN indicating reference data of the signer to include in the message
        	    		new EtsiTs103097Certificate[] {authorizationCert,authorityCACertificate, rootCACertificate}, // The chain is required even though it isn't included in
        	    		  // the message if eventual implicit certificates need to have it's public key reconstructed.
        	    		authorizationTokenSigningKeys.getPrivate()); // Signing Key
        		// It is also possible to generate a EtsiTs103097DataSignedExternalPayload with the genEtsiTs103097DataSignedExternalPayload()
        		// method.
        
        	    // The message can be encrypted with the method
        	      // First construct a list of recipient which have the public key specified either as a symmetric key, certificate or in header of signed data
        	      // In this example we will use certificate as reciever, see package org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient for more details.
        		EtsiTs103097DataEncrypted encryptedData = securedMessageGenerator.genEtsiTs103097DataEncrypted(BasePublicEncryptionKeyChoices.ecdsaNistP256,
        	    		  signedData.getEncoded(), new Recipient[] {new CertificateRecipient(enrollmentCredential)});
        
        	    // It is also possible to sign and encrypt in one go.
        		EtsiTs103097DataEncrypted encryptedAndSignedMessage = securedMessageGenerator.genEtsiTs103097DataSignedAndEncrypted(hi,
        	    		"TestData2".getBytes(),
        	    		SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,
        	    		new EtsiTs103097Certificate[] {authorizationCert,authorityCACertificate, rootCACertificate},
        				authorizationTokenSigningKeys.getPrivate(), // Important to use the reconstructed private key for implicit certificates
        	    		BasePublicEncryptionKeyChoices.ecdsaNistP256,
        	    		new Recipient[] {new CertificateRecipient(enrollmentCredential)});
        
        	    // To decrypt and verify a signed message it is possible to use the following
        	      // First build a truststore of trust anchors (root CA certificate or equivalent)
        	    Map<HashedId8, Certificate> trustStore = securedMessageGenerator.buildCertStore(new EtsiTs103097Certificate[] {rootCACertificate});
        	      // Second build a store of known certificate that might be referenced in the message.
        	    Map<HashedId8, Certificate> certStore = securedMessageGenerator.buildCertStore(new EtsiTs103097Certificate[] {authorizationCert, authorityCACertificate});
        	      // To decrypt build a reciever store of known decryption keys and related receiver info, this can be certificate, signed message containing encryption key
        	      // in header, symmetric key or pre shared key.
        	    Map<HashedId8, Receiver> recieverStore = securedMessageGenerator.buildRecieverStore(new Receiver[] { new CertificateReciever(enrollmentCredentialEncryptionKeys.getPrivate(), enrollmentCredential)});
        		  // Finally perform the decryption and verification of siganture with.
        		DecryptAndVerifyResult decryptAndVerifyResult = securedMessageGenerator.decryptAndVerifySignedData(encryptedAndSignedMessage.getEncoded(),
        	    		certStore,
        	    		trustStore,
        	    		recieverStore,
        	    		true, //requiredSignature true if message must be signed otherwise a IllegalArgument is throwm
        	    		true //requireEncryption true if message must be encrypted otherwise a IllegalArgument is throwm
        	    		);
        		   // The decryptAndVerifyResult contains the inner opaque data, the related header info and signer identifier
        		   // if related message was signed.
        
        	      // It is also possible to use the methods decryptData or verifySignedData (or verifyReferencedSignedData) for alternative methods to verify and decrypt messages.

```


### To Encode and Decode Certificates and Secured Messages

```

	    // To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationCert.getEncoded();
	    
	    // To decode certificate data use the following constructor
	    EtsiTs103097Certificate decodedCertificate = new EtsiTs103097Certificate(certificateData);
		
	    // To decode message data use the following constructor.
	    EtsiTs103097Data decodedMessage = new EtsiTs103097Data(messageData);
	    // If the message profile is known there also exists EtsiTs103097DataSigned, EtsiTs103097DataSignedExternalPayload,
	    // EtsiTs103097DataEncrypted classes that performs validation according to each profile.
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

	    Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();	
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

	    // Now we have the CA hierarchy, the next step is to generate an enrollment credential
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
	    		null, // encryptionKey Optional
				null, // inlineP2pcdRequest Optional
		null // requestedCertificate Optional
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
	    		new Recipient[] {new CertificateRecipient(enrollmentCredential)}).getEncoded();
	    
	    // To decrypt and verify a signed message it is possible to use the following
	      // First build a truststore of trust anchors (root CA certificate or equivalent)
	    Map<HashedId8, Certificate> trustStore = securedMessageGenerator.buildCertStore(new Certificate[] {rootCACertificate});
	      // Second build a store of known certificate that might be referenced in the message.
	    Map<HashedId8, Certificate> certStore = securedMessageGenerator.buildCertStore(new Certificate[] {authorizationCert, authorityCACertificate});
	      // To decrypt build a reciever store of known decryption keys and related receiver info, this can be certificate, signed message containing encryption key
	      // in header, symmetric key or pre shared key.
	    Map<HashedId8, Receiver> recieverStore = securedMessageGenerator.buildRecieverStore(new Receiver[] { new CertificateReciever(enrollmentCredentialEncryptionKeys.getPrivate(), enrollmentCredential)});
		  // Finally perform the decryption with.
		DecryptAndVerifyResult decryptAndVerifyResult = securedMessageGenerator.decryptAndVerifySignedData(encryptedAndSignedMessage,
	    		certStore, 
	    		trustStore,
	    		recieverStore, 
	    		true, //requiredSignature true if message must be signed otherwise a IllegalArgument is throwm
	    		true //requireEncryption true if message must be encrypted otherwise a IllegalArgument is throwm
	    		);
		   // The decryptAndVerifyResult contains the inner opaque data, the related header info and signer identifier
		   // if related message was signed.

	      // It is also possible to use the methods decryptData or verifySignedData (or verifyReferencedSignedData) for alternative methods to verify and decrypt messages.

```

### Secured Data Encoding and Decoding Example 


To encode and decode a secured data use:
		
```

	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedData.getEncoded();
	    
	    // To decode message data use the following constructor.
	    Ieee1609Dot2Data decodedMessage = new Ieee1609Dot2Data(messageData);

```