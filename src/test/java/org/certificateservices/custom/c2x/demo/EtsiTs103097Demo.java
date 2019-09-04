/************************************************************************
*                                                                       *
*  Certificate Service -  Car2Car Core                                  *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.custom.c2x.demo;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.DecryptAndVerifyResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.CertificateRecipient;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;
import org.junit.Test;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class EtsiTs103097Demo {
	
	private final static int SWEDEN = 752;
		
	/**
	 * This example demonstrates how to create a CA Hierarchy and generate Enrollment Credentials and Authorization Tickets,
	 * and EtsiTs103097Data messages using the generator classes in the
	 * org.certificateservices.custom.c2x.etsits103097.v131.generator package.
	 *
	 * ETSI TS 103 097 Data structures are build upon the Ieee 1609.2 Data structures, so can be helpful to also
	 * look at the Ieee1609Dot2Demo class.
	 */
	@Test
	@SuppressWarnings("unused")
	public void demoGenerateCAHierarchyAndSecureMessages() throws Exception{
		// Create a crypto manager in charge of communicating with underlying cryptographic components,
		// The same crypto m
	    Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();	
	    // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
	    cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	    
	    
	    //----------------------------------- Generate CA Hierarchy Example ---------------------------------
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

		System.out.println("Root CA : " + rootCACertificate.toString());
		System.out.println("Encoded: " +Hex.toHexString(rootCACertificate.getEncoded()));
	    		                                                    
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

		System.out.println("-----\n");
		System.out.println("EA CA : " + enrollmentCACertificate.toString());
		System.out.println("Encoded: " + Hex.toHexString(enrollmentCACertificate.getEncoded()));
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

		System.out.println("-----\n");
		System.out.println("AA CA : " + authorityCACertificate.toString());
		System.out.println("Encoded: " +Hex.toHexString(authorityCACertificate.getEncoded()));
		// It is possible to generate Enrollment and Authorization CAs with more flexible extensions using the
		// genSubCA() method.

	    //----------------------------------- Enrollment Credential Example ---------------------------------	    
	    // Now we have the CA hierarchy, the next step is to generate an enrollment credential
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
	    		1, // assuranceLevel
				3, // confidenceLevel
	    		SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
	    		enrollmentCredentialSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
	    		enrollmentCACertificate, // signerCertificate
	    		enrollmentCASigningKeys.getPublic(), // signCertificatePublicKey,
	    		enrollmentCASigningKeys.getPrivate(), 
	    		SymmAlgorithm.aes128Ccm, // symmAlgorithm 
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
	    		enrollmentCredentialEncryptionKeys.getPublic() // encryption public key
	    		);
		System.out.println("-----\n");
		System.out.println("EnrollmentCredential : " + enrollmentCredential.toString());
		System.out.println("Encoded: " +Hex.toHexString(enrollmentCredential.getEncoded()));
	    // There also exists a more general method with flexible app permissions.
	    
	    //----------------------------------- Authorization Certificate Example ---------------------------------
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
		System.out.println("-----\n");
		System.out.println("Authorization Ticket : " + authorizationCert.toString());
		System.out.println("Encoded: " +Hex.toHexString(authorizationCert.getEncoded()));
		//----------------------------------- Trust List Manager Example ---------------------------------
		// Trust List Manager Certificate is generated using ETSIAuthorityCertGenerator

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

	    //----------------------------------- Certificate Encoding and Decoding Example ---------------------------------
	    
	    // To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationCert.getEncoded();
	    
	    // To decode certificate data use the following constructor
		EtsiTs103097Certificate decodedCertificate = new EtsiTs103097Certificate(certificateData);
	    
	    
	    //----------------------------------- Secured Data Example ---------------------------------
	    // EtsiTs103097Data are created by the Secure Message Generator
		ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature);

		// To generate a Signed CA Message it is possible to use
		List<HashedId3> hashedId3s = new ArrayList<HashedId3>();
		hashedId3s.add(new HashedId3(cryptoManager.digest(rootCACertificate.getEncoded(),HashAlgorithm.sha256)));
		hashedId3s.add(new HashedId3(cryptoManager.digest(enrollmentCACertificate.getEncoded(),HashAlgorithm.sha256)));
		SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3(hashedId3s);

		byte[] cAMessageData = Hex.decode("01020304");
		EtsiTs103097DataSigned cAMessage = securedMessageGenerator.genCAMessage(new Time64(new Date()), // generationTime
				inlineP2pcdRequest, //  InlineP2pcdRequest (Required)
				rootCACertificate, // requestedCertificate
				cAMessageData, // inner opaque CA message data
				SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE, // signerIdentifierType
				authorizationCert, // signerCertificate
				authorizationTokenSigningKeys.getPrivate()); // signerPrivateKey


		// To generate a Signed DEN Message
		byte[] dENMessageData = Hex.decode("010203040506");
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
	    		new Date(), // generationTime Optional
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

		//----------------------------------- Secured Data Encoding and Decoding Example ---------------------------------
	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedData.getEncoded();
	    
	    // To decode message data use the following constructor.
		EtsiTs103097Data decodedMessage = new EtsiTs103097Data(messageData);
		// If the message profile is known there also exists EtsiTs103097DataSigned, EtsiTs103097DataSignedExternalPayload,
		// EtsiTs103097DataEncrypted classes that performs validation according to each profile.
	}

}
