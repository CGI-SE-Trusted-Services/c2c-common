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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator.SignerIdentifierType;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.CertificateRecipient;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;
import org.junit.Test;

public class Ieee1609Dot2Demo {
	
	final static int SWEDEN = 752;
		
	/**
	 * This example demonstrates how to create a CA Hierarchy and generate Enrollment Certificates and Authorization Certificates 
	 * using the generator classes in the org.certificateservices.custom.c2x.ieee1609dot2.generator package.
	 */
	@Test
	@SuppressWarnings("unused")
	public void demoGenerateCAHierarchyAndSecureMessages() throws Exception{
		// Create a crypto manager in charge of communicating with underlying cryptographic components
	    Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();	
	    // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
	    cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	    
	    
	    //----------------------------------- Generate CA Hierarchy Example ---------------------------------
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
	    
	    //----------------------------------- Enrollment Credential Example ---------------------------------	    
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
	    
	    //----------------------------------- Authorization Certificate Example ---------------------------------
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
	    
	    //----------------------------------- Certificate Encoding and Decoding Example ---------------------------------
	    
	    // To encode a certificate to a byte array use the following method
	    byte[] certificateData = authorizationCert.getEncoded();
	    
	    // To decode certificate data use the following constructor
	    Certificate decodedCertificate = new Certificate(certificateData);
	    
	    
	    //----------------------------------- Secured Data Example ---------------------------------
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
	    EncryptResult encryptResult = securedMessageGenerator.encryptData(BasePublicEncryptionKeyChoices.ecdsaNistP256,
	    		  signedData.getEncoded(), new Recipient[] {new CertificateRecipient(enrollmentCredential)});
		Ieee1609Dot2Data encryptedData = encryptResult.getEncryptedData();
	      // It is also possible to encrypt using a pre shared key using the encryptDataWithPresharedKey() method.
	    
	    // It is also possible to sign and encrypt in one go.
	    byte[] encryptedAndSignedMessage = securedMessageGenerator.signAndEncryptData(hi, 
	    		"TestData2".getBytes(), 
	    		SignerIdentifierType.HASH_ONLY, 
	    		new Certificate[] {authorizationCert,authorityCACertificate, rootCACertificate}, 
	    		authorizationCertSigningPrivateKey, // Important to use the reconstructed private key for implicit certificates
	    		BasePublicEncryptionKeyChoices.ecdsaNistP256, 
	    		new Recipient[] {new CertificateRecipient(enrollmentCredential)}).getEncryptedData().getEncoded();
	    
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

		//----------------------------------- Secured Data Encoding and Decoding Example ---------------------------------
	    // To encode a secured message to a byte array use the following method.
	    byte[] messageData = signedData.getEncoded();
	    
	    // To decode message data use the following constructor.
	    Ieee1609Dot2Data decodedMessage = new Ieee1609Dot2Data(messageData);
	}

}
