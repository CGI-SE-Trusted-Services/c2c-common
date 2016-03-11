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

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType;
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator;
import org.certificateservices.custom.c2x.its.generator.AuthorizationTicketCertGenerator;
import org.certificateservices.custom.c2x.its.generator.EnrollmentCredentialCertGenerator;
import org.certificateservices.custom.c2x.its.generator.SecuredMessageGenerator;
import org.junit.Test;

public class ITSDemo {
	
		
	/**
	 * This example demonstrates how to create a CA Hierarchy and generate Enrollment Certificates and Authorization Certificates using the Generator classes in the org.certificateservices.custom.c2x.its.generator package.
	 */
	@Test
	@SuppressWarnings("unused")
	public void demoGenerateCAHierarchyAndSecureMessages() throws Exception{
		// Create a crypto manager in charge of communicating with underlying cryptographic components
	    ITSCryptoManager cryptoManager = new DefaultCryptoManager();	
	    // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
	    cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	    
	    
	    //----------------------------------- Generate CA Hierarchy Example ---------------------------------
	    // Create an authority certificate generator and initialize it with the crypto manager. 
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
	    
	    // Generate a reference to the Authorization CA Signing Keys	    
	    KeyPair authorityCASigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Authorization CA
	    List<BigInteger> authorityCAItsAidList = new ArrayList<BigInteger>();
	    authorityCAItsAidList.add(new BigInteger("3"));

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
	    
	    //----------------------------------- Enrollment Credential Example ---------------------------------	    
	    // Now we have the CA hierarchy, the next step is to generate an enrollment credential
	    // First we create a Enrollment Credential Cert Generator using the newly created Enrollment CA.
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
	    		SignerInfoType.certificate,//signerInfoType 
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
	    
	    //----------------------------------- Authorization Ticket Example ---------------------------------
	    // Authorization Tickets are created by the AuthorizationTicketCertGenerator
	    AuthorizationTicketCertGenerator authorizationTicketCertGenerator = new AuthorizationTicketCertGenerator(cryptoManager, authorityCACertificate, authorityCASigningKeys.getPrivate());
	    
	    // Next we generate keys for an authorization ticket.
	    KeyPair authorizationTicketSigningKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Next we generate keys for an authorization ticket.
	    KeyPair authorizationTicketEncryptionKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
	    
	    // Generate the list of ITS AID values for the Authorization Ticket
	    List<BigInteger> authTicketItsAidList = new ArrayList<BigInteger>();
	    authTicketItsAidList.add(new BigInteger("4"));
	    
	    Certificate authorizationTicket = authorizationTicketCertGenerator.genAuthorizationTicket(
	    		SignerInfoType.certificate,//signerInfoType 
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
	    
	    //----------------------------------- Certificate Encoding and Decoding Example ---------------------------------
	    
	    // To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationTicket.getEncoded();
	    
	    // To decode certificate data use the following constructor
	    Certificate decodedCertificate = new Certificate(certificateData);
	    
	    //----------------------------------- CAM Message Example ---------------------------------
	    // Secure Messages are created by the Secure Message Generator
	    SecuredMessageGenerator securedMessageGenerator = new SecuredMessageGenerator(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicket, authorityCASigningKeys.getPrivate(), PublicKeyAlgorithm.ecies_nistp256, authorizationTicketEncryptionKeys.getPrivate());
	    
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
		
		//----------------------------------- Generating a Encrypted Secured Message Example ---------------------------------
		// Neither CAM nor DENM messages should be encrypted, so in this example is a SecureMessage built manually
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
		headerFields.add(new HeaderField(generationLocation));
        headerFields.add(new HeaderField(123)); // Just have any value since no known message type uses encryption
        
        // There is no need to add recipient_info or encryption_parameters, these will be calculated and appended automatically by the crypto manager.
		List<Payload> payloadFields = new ArrayList<Payload>();
		// The payload that should be encrypted should have type encrypted, others will be ignored.
		payloadFields.add(new Payload(PayloadType.encrypted,"SomeClearText".getBytes("UTF-8")));
		
		SecuredMessage secureMessage = new SecuredMessage(SecuredMessage.DEFAULT_SECURITY_PROFILE, headerFields, payloadFields);
		
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
		
		//----------------------------------- Generating a Sign And Encrypted Secured Message Example -----------------------
		// In this example we generate messages with payload type signed_and_encrypted, i.e the data is both signed and encrypted
		
		// We start with constructing a secured message
		headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
		headerFields.add(new HeaderField(generationLocation));
        headerFields.add(new HeaderField(123)); // Just have any value since no known message type uses encryption
        
        // There is no need to add recipient_info or encryption_parameters, these will be calculated and appended automatically by the crypto manager.
		payloadFields = new ArrayList<Payload>();
		// The payload that should be encrypted should have type encrypted, others will be ignored.
		payloadFields.add(new Payload(PayloadType.signed_and_encrypted,"SomeClearText".getBytes("UTF-8")));
		
		secureMessage = new SecuredMessage(SecuredMessage.DEFAULT_SECURITY_PROFILE, headerFields, payloadFields);
		
		SecuredMessage encryptedAndSignedMessage = cryptoManager.encryptAndSignSecureMessage(secureMessage, enrollmentCredential, SignerInfoType.certificate, 
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
		
		//----------------------------------- Secured Message Encoding and Decoding Example ---------------------------------
	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedDENMMessage.getEncoded();
	    
	    // To decode message data use the following constructor.
	    SecuredMessage decodedMessage = new SecuredMessage(messageData);
	}

}
