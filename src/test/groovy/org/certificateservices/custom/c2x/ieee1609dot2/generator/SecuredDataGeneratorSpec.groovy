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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo.RecipientInfoChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext.SymmetricCiphertextChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator.SignerIdentifierType
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.*
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.*
import spock.lang.Unroll

import javax.crypto.SecretKey
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.text.SimpleDateFormat

/**
 * Test for SecuredDataGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SecuredDataGeneratorSpec extends BaseCertGeneratorSpec {

	@Unroll
	def "Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)
		PrivateKey enrollCertPrivateKey = ecqvHelper.certReceiption(enrollCert, enrollCert.r, alg, enrollCertKeys.privateKey, enrollCAPubKey, enrollCA)
		SecuredDataGenerator sdg = sdg_ecdsaNistP256
		if(alg == PublicVerificationKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,null,null,null)
		when:
		Ieee1609Dot2Data sd = sdg.genSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.HASH_ONLY,[enrollCert, enrollCA, rootCA] as Certificate[], enrollCertPrivateKey)
		then:
		sd.getContent().getType() == Ieee1609Dot2ContentChoices.signedData
		SignedData signedData = sd.getContent().getValue()
		signedData.getSignature() != null
		signedData.getSigner().getType() == SignerIdentifierChoices.digest
		signedData.getTbsData().getHeaderInfo() == hi
		Ieee1609Dot2Data unsecuredData = ((SignedDataPayload) signedData.getTbsData().getPayload()).getData()
		unsecuredData.getContent().getType() == Ieee1609Dot2ContentChoices.unsecuredData
		unsecuredData.getContent().getValue().getData() == "TestData".getBytes("UTF-8")

		when:
		def certStore = sdg.buildCertStore([enrollCA,enrollCert])
		def trustStore = sdg.buildCertStore([rootCA])
		then:
		sdg.verifySignedData(sd,  certStore, trustStore)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}


	@Unroll
	def "Verify that signed Ieee1609Dot2Data with hashed reference is generated correctly for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)
		PrivateKey enrollCertPrivateKey = ecqvHelper.certReceiption(enrollCert, enrollCert.r, alg, enrollCertKeys.privateKey, enrollCAPubKey, enrollCA)
		SecuredDataGenerator sdg = sdg_ecdsaNistP256
		if(alg == PublicVerificationKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,null,null,null)

		when:
		Ieee1609Dot2Data sd = sdg.genReferencedSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.CERT_CHAIN,[enrollCert, enrollCA, rootCA] as Certificate[], enrollCertPrivateKey)

		then:
		sd.getContent().getType() == Ieee1609Dot2ContentChoices.signedData
		SignedData signedData = sd.getContent().getValue()
		signedData.getSignature() != null
		signedData.getSigner().getType() == SignerIdentifierChoices.certificate
		signedData.getTbsData().getHeaderInfo() == hi
		HashedData hashedData = ((SignedDataPayload) signedData.getTbsData().getPayload()).getExtDataHash()
		hashedData.getType() == HashedDataChoices.sha256HashedData
		hashedData.getValue().getData() == cryptoManager.digest("TestData".getBytes("UTF-8"), HashAlgorithm.sha256)

		when:
		def trustStore = sdg.buildCertStore([rootCA])
		then:
		sdg.verifyReferencedSignedData(sd, "TestData".getBytes("UTF-8"), [:], trustStore)
		!sdg.verifyReferencedSignedData(sd, "InvalidData".getBytes("UTF-8"), [:], trustStore)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	
	def "Verify that preshared key encryption works correctly"(){
		setup:
		SecretKey k1 = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)
		SecretKey k2 = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)
		
		byte[] clearText = "SomeText".getBytes("UTF-8")
		when:
		Ieee1609Dot2Data enc = sdg.encryptDataWithPresharedKey(SymmAlgorithm.aes128Ccm, clearText, k1)
		then:
		enc.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		EncryptedData ed = enc.getContent().getValue();
		ed.getRecipients().size() == 1
		RecipientInfo ri = ed.getRecipients().getSequenceValuesAsList()[0]
		ri.getType() == RecipientInfoChoices.pskRecipInfo
		ri.getValue() == sdg.getSecretKeyID(SymmAlgorithm.aes128Ccm,k1)
		ed.getCipherText().getType() == SymmetricCiphertextChoices.aes128ccm
		
		when: "Verify that text is decrypted correclty for a known key"
		byte[] decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,k1),new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,k2)]))
		then:
		decryptedText == clearText
		
		when: "Verify that illegal argument is thrown if key is not known"
		sdg.decryptData(enc,  sdg.buildRecieverStore([new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,k2)]))
		then:
		thrown IllegalArgumentException
		
		when: "Verify  that illegal argument is thrown if symmetric key store is null "
		sdg.decryptData(enc, null)
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify that symmetric key envelope encryption works correctly"(){
		setup:
		SecretKey k1 = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)
		SecretKey k2 = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)
		SecretKey k3 = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)
		
		byte[] clearText = "SomeText".getBytes("UTF-8")
		when:
		Ieee1609Dot2Data enc = sdg.encryptData(SymmAlgorithm.aes128Ccm, clearText, [new SymmetricKeyReceipient(SymmAlgorithm.aes128Ccm,k1),new SymmetricKeyReceipient(SymmAlgorithm.aes128Ccm,k2)] as Recipient[])
		
		then:
		enc.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		EncryptedData ed = enc.getContent().getValue();
		ed.getRecipients().size() == 2
		RecipientInfo ri = ed.getRecipients().getSequenceValuesAsList()[0]
		ri.getType() == RecipientInfoChoices.symmRecipInfo
		((SymmRecipientInfo) ri.getValue()).getRecipientId() == sdg.getSecretKeyID(SymmAlgorithm.aes128Ccm,k1)
		ed.getCipherText().getType() == SymmetricCiphertextChoices.aes128ccm
		
		when: "Verify that text is decrypted correclty for a known key"
		byte[] decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new SymmetricKeyReceiver(SymmAlgorithm.aes128Ccm,k1),new SymmetricKeyReceiver(SymmAlgorithm.aes128Ccm,k3)]))
		then:
		decryptedText == clearText
		
		when: "Verify that text is decrypted correclty for alternate known key"
		decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new SymmetricKeyReceiver(SymmAlgorithm.aes128Ccm,k2)]))
		then:
		decryptedText == clearText
		
		
		when: "Verify that illegal argument is thrown if key is not known"
		sdg.decryptData(enc,  sdg.buildRecieverStore([new SymmetricKeyReceiver(SymmAlgorithm.aes128Ccm,k3)]))
		then:
		thrown IllegalArgumentException

			
	}
	

	@Unroll
	def "Verify that encryption works with certificate public encryption key for alg: #alg"(){
		setup:
		def sdg = sdg_ecdsaNistP256
		if(alg == BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, alg, encKeys1.publicKey)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2= genEnrollCert(CertificateType.implicit, alg, enrollCertKeys2, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, alg, encKeys2.publicKey)
		
		when:
		byte[] clearText = "SomeText".getBytes("UTF-8")
		Ieee1609Dot2Data enc = sdg.encryptData(alg, clearText, [new CertificateRecipient(enrollCert1)] as Recipient[])
		
		then:
		enc.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		EncryptedData ed = enc.getContent().getValue();
		ed.getRecipients().size() == 1
		RecipientInfo ri = ed.getRecipients().getSequenceValuesAsList()[0]
		ri.getType() == RecipientInfoChoices.certRecipInfo
		((PKRecipientInfo) ri.getValue()).getRecipientId() == sdg.getCertID(enrollCert1)
		ed.getCipherText().getType() == SymmetricCiphertextChoices.aes128ccm
		
		when: "Verify that text is decrypted correctly for a known key"
		byte[] decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new CertificateReciever(encKeys2.privateKey,enrollCert2),new CertificateReciever(encKeys1.privateKey,enrollCert1)]))
		then:
		decryptedText == clearText
		
		when: "Verify that invalid key for a given certificate throws InvalidKeyException"
		sdg.decryptData(enc, sdg.buildRecieverStore([new CertificateReciever(encKeys2.privateKey,enrollCert1)]))
		then:
		thrown InvalidKeyException
		
		when: "Verify that unknown receiver throws IllegalArgumentException"
		sdg.decryptData(enc, sdg.buildRecieverStore([new CertificateReciever(encKeys2.privateKey,enrollCert2)]))
		then:
		thrown IllegalArgumentException
		
		where:
		alg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}

	@Unroll
	def "Verify that encryption works with secured data public encryption key for alg: #alg"(){
		setup:
		def sdg = sdg_ecdsaNistP256
		if(alg == BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, null,null)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2= genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, null,null)
		
		KeyPair encKeys1 = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys2 = cryptoManager.generateKeyPair(alg)

		Ieee1609Dot2Data sd1 = sdg.genSignedData(sdg.genHeaderInfo(1234, null,null,null,null,null,null, alg, encKeys1.public,null,null), "TestMessage1".getBytes(), SignerIdentifierType.SIGNER_CERTIFICATE, [enrollCert1] as Certificate[], enrollCertKeys1.private)
		Ieee1609Dot2Data sd2 = sdg.genSignedData(sdg.genHeaderInfo(1234, null,null,null,null,null,null, alg, encKeys2.public,null,null), "TestMessage2".getBytes(), SignerIdentifierType.SIGNER_CERTIFICATE, [enrollCert2] as Certificate[], enrollCertKeys2.private)
		
		byte[] sd1Hash = cryptoManager.digest(sd1.getEncoded(), HashAlgorithm.sha256);
		when:
		byte[] clearText = "SomeText".getBytes("UTF-8")
		Ieee1609Dot2Data enc = sdg.encryptData(alg, clearText, [new SignedDataRecipient(sd1)] as Recipient[])
		
		then:
		enc.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		EncryptedData ed = enc.getContent().getValue();
		ed.getRecipients().size() == 1
		RecipientInfo ri = ed.getRecipients().getSequenceValuesAsList()[0]
		ri.getType() == RecipientInfoChoices.signedDataRecipInfo
		((PKRecipientInfo) ri.getValue()).getRecipientId() == new HashedId8(sd1Hash)
		ed.getCipherText().getType() == SymmetricCiphertextChoices.aes128ccm
		
		when: "Verify that text is decrypted correclty for a known key"
		byte[] decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new SignedDataReciever(encKeys2.private, sd2), new SignedDataReciever(encKeys1.private, sd1)]))
		then:
		decryptedText == clearText
		
		when: "Verify that invalid key exception is thrown if wrong key is used with correct message"
		sdg.decryptData(enc, sdg.buildRecieverStore([new SignedDataReciever(encKeys2.private, sd1)]))
		then:
		thrown InvalidKeyException
		
		when: "Verify that unknown receiver throws IllegalArgumentException"
		sdg.decryptData(enc, sdg.buildRecieverStore([new SignedDataReciever(encKeys2.private, sd2)]))
		then:
		thrown IllegalArgumentException
		
		where:
		alg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that encryption works with RekReceipient for alg: #alg"(){
		setup:
		def sdg = sdg_ecdsaNistP256
		if(alg == BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, null,null)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2= genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, null,null)
		
		KeyPair encKeys1 = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys2 = cryptoManager.generateKeyPair(alg)
		
		byte[] keyHash = cryptoManager.digest(encKeys1.getPublic().getEncoded(), HashAlgorithm.sha256);
		when:
		byte[] clearText = "SomeText".getBytes("UTF-8")
		Ieee1609Dot2Data enc = sdg.encryptData(alg, clearText, [new RekReceipient(encKeys1.getPublic())] as Recipient[])
		
		then:
		enc.getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		EncryptedData ed = enc.getContent().getValue()
		ed.getRecipients().size() == 1
		RecipientInfo ri = ed.getRecipients().getSequenceValuesAsList()[0]
		ri.getType() == RecipientInfoChoices.rekRecipInfo
		((PKRecipientInfo) ri.getValue()).getRecipientId() == new HashedId8(keyHash)
		ed.getCipherText().getType() == SymmetricCiphertextChoices.aes128ccm
		
		when: "Verify that text is decrypted correclty for a known key"
		byte[] decryptedText = sdg.decryptData(enc, sdg.buildRecieverStore([new RekReciever(encKeys2.private, encKeys2.public), new RekReciever(encKeys1.private, encKeys1.public)]))
		then:
		decryptedText == clearText
		
		when: "Verify that invalid key exception is thrown if wrong key is used with correct message"
		sdg.decryptData(enc, sdg.buildRecieverStore([new RekReciever(encKeys2.private, encKeys1.public)]))
		then:
		thrown InvalidKeyException
		
		when: "Verify that unknown receiver throws IllegalArgumentException"
		sdg.decryptData(enc, sdg.buildRecieverStore([new RekReciever(encKeys2.private, encKeys2.public)]))
		then:
		thrown IllegalArgumentException
		
		where:
		alg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}

	def "Verify that genHeaderInfo generates correct header info"(){
		when: "Generate full header"
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd")
		Date genDate = sdf.parse("2016-01-01")
		Date expDate = sdf.parse("2016-02-01")
		KeyPair kp = cryptoManager.generateKeyPair(BasePublicEncryptionKeyChoices.ecdsaNistP256)
		SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3([new HashedId3(Hex.decode("ab1232")), new HashedId3(Hex.decode("ab1233"))])
		Certificate requestedCertificate = deserializeFromHex(new Certificate(),"80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		HeaderInfo hi = sdg.genHeaderInfo(123L, genDate, expDate, new ThreeDLocation(3, 2, 1), Hex.decode("101112"),Hex.decode("131415"), 99, BasePublicEncryptionKeyChoices.ecdsaNistP256, kp.getPublic(),inlineP2pcdRequest,requestedCertificate)
		then:
		hi.psid.valueAsLong == 123L
		hi.generationTime.asDate() == genDate
		hi.expiryTime.asDate() == expDate
		hi.generationLocation.latitude.valueAsLong == 3
		hi.generationLocation.longitude.valueAsLong == 2
		hi.generationLocation.elevation.elevationInDecimeters == 1
		hi.p2pcdLearningRequest.data == Hex.decode("101112")
		hi.missingCrlIdentifier.cracaid.data == Hex.decode("131415")
		hi.missingCrlIdentifier.crlSeries.valueAsLong == 99
		hi.inlineP2pcdRequest == inlineP2pcdRequest
		hi.requestedCertificate == requestedCertificate
		BasePublicEncryptionKey encKey = ((PublicEncryptionKey) hi.encryptionKey.value).publicKey
		cryptoManager.decodeEccPoint(encKey.type, encKey.value) == kp.public
		
		when: "Generate minimal header"
		hi = sdg.genHeaderInfo(124L, null, null, null, null, null, null, null, null,null,null)
		then:
		hi.psid.valueAsLong == 124L
		hi.generationTime == null
		hi.expiryTime == null
		hi.generationLocation == null
		hi.p2pcdLearningRequest == null
		hi.missingCrlIdentifier == null
		hi.encryptionKey == null
		
		when: "Verify that Illegal Argument Exception is thrown if not both missing crl arguments are set"
		sdg.genHeaderInfo(124L, null, null, null, null, Hex.decode("131415"), null, null, null,null,null)
		then:
		thrown IllegalArgumentException
		when:
		sdg.genHeaderInfo(124L, null, null, null, null, null, 99, null, null,null,null)
		then:
		thrown IllegalArgumentException
		
		when: "Verify that Illegal Argument Exception is thrown if not both encryption key are set"
		sdg.genHeaderInfo(124L, null, null, null, null, null, null, BasePublicEncryptionKeyChoices.ecdsaNistP256, null,null,null)
		then:
		thrown IllegalArgumentException
		when:
		sdg.genHeaderInfo(124L, null, null, null, null, null, null, null, kp.getPublic(),null,null)
		then:
		thrown IllegalArgumentException
	}
	
	
	@Unroll
	def "Verify that signAndEncryptData and decryptAndVerifySignedData generates encrypted and signed data structures for alg: #alg"(){
		setup:
		def sdg = sdg_ecdsaNistP256
		if(certAlg == PublicVerificationKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		if(certAlg == PublicVerificationKeyChoices.ecdsaBrainpoolP384r1){
			sdg = sdg_ecdsaBrainpoolP384r1
		}
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(certAlg)
		Certificate rootCA = genRootCA(rootCAKeys,certAlg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(certAlg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, certAlg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(certAlg)
		KeyPair encKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, certAlg, enrollCertKeys1, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, alg, encKeys1.publicKey)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(certAlg)
		KeyPair encKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2= genEnrollCert(CertificateType.explicit, certAlg, enrollCertKeys2, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA, alg, encKeys2.publicKey)
		
		
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,null,null,null)
		def certStore = sdg.buildCertStore([enrollCA,enrollCert1])
		def trustStore = sdg.buildCertStore([rootCA])
		when:
		byte[] encData = sdg.signAndEncryptData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.HASH_ONLY, [enrollCert1, enrollCA, rootCA] as Certificate[], enrollCertKeys1.private, alg, [new CertificateRecipient(enrollCert2)] as Recipient[]).getEncoded()
		
		then:
		new Ieee1609Dot2Data(encData).getContent().getType() == Ieee1609Dot2ContentChoices.encryptedData
		when:
		DecryptAndVerifyResult r = sdg.decryptAndVerifySignedData(encData, certStore, trustStore, sdg.buildRecieverStore([new CertificateReciever(encKeys2.privateKey,enrollCert2)]), true, true)
		
		then:
		r.headerInfo == hi
		r.signerIdentifier.type == SignerIdentifierChoices.digest
		r.data == "TestData".getBytes("UTF-8")
		
		
		when: "Verify that decrypt and verify returns a verified only if a signed data is given and encryption isn't required"
		byte[] signedData = sdg.genSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.HASH_ONLY, [enrollCert1, enrollCA, rootCA] as Certificate[], enrollCertKeys1.private).encoded
		r = sdg.decryptAndVerifySignedData(signedData, certStore, trustStore, null, true, false)
		then:
		r.data == "TestData".getBytes("UTF-8")
		
		when: "Verify that decrypt and verify thrown IllegalArgumentException if data is not encrypted but required"
		sdg.decryptAndVerifySignedData(signedData, certStore, trustStore, null, true, true)
		then:
		thrown IllegalArgumentException
		
		when: "Verify that decrypt and verify returns unencrypted data if enryption and signature isn't required"
		byte[] ensecured = new Ieee1609Dot2Data(new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData, new Opaque("TestData".getBytes("UTF-8")))).encoded
		r = sdg.decryptAndVerifySignedData(ensecured, null, null, null, false, false)
		then:
		r.headerInfo == null
		r.signerIdentifier == null
		r.data == "TestData".getBytes("UTF-8")
		
		when: "Verify that decrypt and verify thrown IllegalArgumentException for unencrypted data if signature is required"
		sdg.decryptAndVerifySignedData(ensecured, certStore, trustStore, null, true, false)
		then:
		thrown IllegalArgumentException
		
		when: "Verify that decrypt and verify returns decrypted data but doesn't verify data in not required, i.e encrypted data contains unsecuredData"
		byte[] encDataOnly = sdg.encryptData(alg, ensecured,  [new CertificateRecipient(enrollCert2)] as Recipient[]).encoded
		r = sdg.decryptAndVerifySignedData(encDataOnly, null, null, sdg.buildRecieverStore([new CertificateReciever(encKeys2.privateKey,enrollCert2)]), false, true)
		then:
		r.data == "TestData".getBytes("UTF-8")
		
		where:
		certAlg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, PublicVerificationKeyChoices.ecdsaBrainpoolP384r1]
		alg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	def "Verify that return first certificates public key of complete chain consists of explicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertKeys.publicKey
	}

	def "Verify that return first certificates public key of enroll cert only consists of implicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAKeys.publicKey, alg, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertExtractedKey
	}

	def "Verify that return first certificates public key of enroll cert and enroll ca consists of implicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertExtractedKey
	}

	def "Verify that getSignerIdentifier returns correct self as type for type SELF"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.SELF, [rootCA]  as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.self
	}

	def "Verify that getSignerIdentifier returns correct hash value for type HASH_ONLY"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.HASH_ONLY, [rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.digest
		si.getValue() instanceof HashedId8
		si.getValue() == new HashedId8(cryptoManager.digest(rootCA.encoded, alg))
	}


	def "Verify that getSignerIdentifier returns first signing certificate from a chain for type SIGNER_CERTIFICATE"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.SIGNER_CERTIFICATE, [enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.certificate
		si.getValue() instanceof SequenceOfCertificate
		((SequenceOfCertificate) si.getValue()).getSequenceValuesAsList()[0] == enrollCert
	}

	def "Verify that getSignerIdentifier returns first signing certificate from a chain for type CERT_CHAIN"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.CERT_CHAIN, [enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.certificate
		si.getValue() instanceof SequenceOfCertificate
		List certs = ((SequenceOfCertificate) si.getValue()).getSequenceValuesAsList()
		certs.size() == 2
		certs[0] == enrollCert
		certs[1] == enrollCA
	}
	
	def "Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate rootCA1 = genRootCA(rootCAKeys1)
		HashedId8 rootCA1Id = sdg.getCertID(rootCA1)
		KeyPair rootCAKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate rootCA2 = genRootCA(rootCAKeys2)
		HashedId8 rootCA2Id = sdg.getCertID(rootCA2)
		KeyPair enrollCAKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA1 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys1, rootCAKeys1, rootCA1)
		HashedId8 enrollCA1Id = sdg.getCertID(enrollCA1)
		KeyPair enrollCAKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA2 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys2, rootCAKeys2, rootCA2)
		HashedId8 enrollCA2Id = sdg.getCertID(enrollCA2)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys1.publicKey, enrollCAKeys1.privateKey, enrollCA1)
		HashedId8 enrollCert1Id = sdg.getCertID(enrollCert1)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys2.publicKey, enrollCAKeys2.privateKey, enrollCA2)
		HashedId8 enrollCert2Id = sdg.getCertID(enrollCert2)

		when: "Verify that buildCertStore generates correct stores"
		Map<HashedId8, Certificate> trustStore = sdg.buildCertStore([rootCA1, rootCA2] as Certificate[])
		Map<HashedId8, Certificate> certStore1 = sdg.buildCertStore([enrollCA1, enrollCA2, enrollCert1] as Certificate[])
		Map<HashedId8, Certificate> certStore2 = sdg.buildCertStore([enrollCA1, enrollCA2, rootCA2] as Certificate[])
		Map<HashedId8, Certificate> signedDataStore1 = sdg.buildCertStore([enrollCA2, enrollCert2] as Certificate[])
		Map<HashedId8, Certificate> signedDataStore2 = sdg.buildCertStore([enrollCert2] as Certificate[])
		then: 
		trustStore.size() == 2
		trustStore.get(rootCA1Id) == rootCA1
		trustStore.get(rootCA2Id) == rootCA2
		
		certStore1.size() == 3
		certStore1.get(enrollCA1Id) == enrollCA1
		certStore1.get(enrollCA2Id) == enrollCA2
		certStore1.get(enrollCert1Id) == enrollCert1
		

		when: "Verify that buildChain constructs a correct chain for a root ca only chain"
		Certificate[] c = sdg.buildChain(rootCA2Id, signedDataStore1, certStore1, trustStore)
		then:
		c.length == 1
		c[0] == rootCA2
		
		when: "Verify that buildChain constructs a chain from all three stores"
		c = sdg.buildChain(enrollCert2Id, signedDataStore1, certStore1, trustStore)
		then:
		c.length == 3
		c[0] == enrollCert2
		c[1] == enrollCA2
		c[2] == rootCA2
		
		when: "Verify that illegal argument is found if signing certificate cannot be found"
		sdg.buildChain(enrollCert2Id, [:], [:], [:])
		then:
		thrown IllegalArgumentException
		
		when: "Verify that illegal argument is found if root certificate cannot be found as trust anchor"
		sdg.buildChain(enrollCert2Id, signedDataStore1, certStore2, [:])
		then:
		thrown IllegalArgumentException
		
		when: "Verify that illegal argument is found if intermediate certificate cannot be found"
		sdg.buildChain(enrollCert2Id, signedDataStore2, [:], trustStore)
		then:
		thrown IllegalArgumentException
	}

	def "Verify that findFromStores finds certificate from stores"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		HashedId8 certId = sdg.getCertID(enrollCA)
		HashedId8 rootCertId = sdg.getCertID(rootCA)
		expect:
		sdg.findFromStores(certId, [(certId):enrollCA], [:], [:]) == enrollCA
		sdg.findFromStores(certId, [:],[(certId):enrollCA], [:]) == enrollCA
		sdg.findFromStores(rootCertId, [:],[:],[(rootCertId):rootCA]) == rootCA
		sdg.findFromStores(certId, [:],[:],[:]) == null
		
		when: "Verify that implicit trust ancor generates IllegalArgumentException"
		sdg.findFromStores(certId, [:],[:],[(certId):enrollCA])
		
		then:
		thrown IllegalArgumentException
		
	}
	
	def "Verify getCertID generates a correct HashedId8"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)

		when:
		HashedId8 certId = sdg.getCertID(rootCA)
		then:
		certId == new HashedId8(cryptoManager.digest(rootCA.getEncoded(), HashAlgorithm.sha256))
	}

	def "Verify that getSignerId throws IllegalArgumentException if SignerIdentifier is self"(){
		when:
		sdg.getSignerId(new SignerIdentifier())
		then:
		thrown IllegalArgumentException
	}

	def "Verify that getSignerId returns the included HashedId8 if type is digest"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		def certId = sdg.getCertID(rootCA)
		expect:
		sdg.getSignerId(new SignerIdentifier(certId)) == certId
	}

	def "Verify that getSignedDataStore returns the HashedId8 of the first certificate if type is certificate"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		def certId = sdg.getCertID(enrollCA)
		expect:
		sdg.getSignerId(new SignerIdentifier(new SequenceOfCertificate([enrollCA, rootCA]))) == certId

	}

	def "Verify that getSignedDataStore returns an empty map if SignerIdentifier is self"(){
		expect:
		sdg.getSignedDataStore(new SignerIdentifier()).size() == 0
	}

	def "Verify that getSignedDataStore returns an empty map if SignerIdentifier is digest"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		expect:
		sdg.getSignedDataStore(new SignerIdentifier(sdg.getCertID(rootCA))).size() == 0
	}

	def "Verify that getSignedDataStore returns a populate map of all certificate if SignerIdentifier is certificate"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		when:
		Map<HashedId8, Certificate> result = sdg.getSignedDataStore(new SignerIdentifier(new SequenceOfCertificate([enrollCA, rootCA])))

		then:
		result.size() == 2
		result.get(sdg.getCertID(rootCA)) == rootCA
		result.get(sdg.getCertID(enrollCA)) == enrollCA
	}
	


	def "Verify that buildRecieverStore generates a correct HashedId8 to Receiver Map"(){
		setup:
		def alg = BasePublicEncryptionKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate rootCA1 = genRootCA(rootCAKeys1)
		HashedId8 rootCA1Id = sdg.getCertID(rootCA1)
		SecretKey sharedKey = cryptoManager.generateSecretKey(alg)
		HashedId8 sharedKeyId = sdg.getSecretKeyID(SymmAlgorithm.aes128Ccm,sharedKey)
		SecretKey symKey = cryptoManager.generateSecretKey(alg)
		HashedId8 symKeyId = sdg.getSecretKeyID(SymmAlgorithm.aes128Ccm,symKey)
		KeyPair rekKeys = cryptoManager.generateKeyPair(alg)
		HashedId8 rekKeyId = new HashedId8(cryptoManager.digest(rekKeys.getPublic().getEncoded(), alg))
		
		KeyPair signedDataEncKeys1 = cryptoManager.generateKeyPair(alg)
		Ieee1609Dot2Data signedData = genSignedData([rootCA1] as Certificate[], rootCAKeys1.getPrivate(), BasePublicEncryptionKeyChoices.ecdsaNistP256,signedDataEncKeys1.publicKey)
		HashedId8 signedDataId = new HashedId8(cryptoManager.digest(signedData.encoded, alg))
		
		when:
		Map res = sdg.buildRecieverStore([new CertificateReciever((PrivateKey) rootCAKeys1.privateKey, rootCA1), 
			new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,sharedKey), new SymmetricKeyReceiver(SymmAlgorithm.aes128Ccm,symKey),
			new RekReciever(rekKeys.getPrivate(), rekKeys.getPublic()),
			new SignedDataReciever(signedDataEncKeys1.privateKey, signedData)])
		
		then:
		res.size() == 5
		res[rootCA1Id].privateKey == rootCAKeys1.privateKey
		res[sharedKeyId].secretKey == sharedKey
		res[symKeyId].symmetricKey == symKey
		res[rekKeyId].publicKey == rekKeys.publicKey
		res[signedDataId].signedData == signedData
		
		when:
		res = sdg.buildRecieverStore([new CertificateReciever((PrivateKey) rootCAKeys1.privateKey, rootCA1)] as CertificateReciever[])
		
		then:
		res.size() == 1
	}
	
	@Unroll
	def "Verify getHashedDataChoice()"(){
		setup:
		sdg_ecdsaNistP256.hashAlgorithm = hashAlg
		expect:
		sdg_ecdsaNistP256.getHashedDataChoice() == choice
		where:
		hashAlg                    | choice
		HashAlgorithm.sha256       | HashedDataChoices.sha256HashedData

	}
	
	private Ieee1609Dot2Data genSignedData(Certificate[] certChain, PrivateKey privateKey, BasePublicEncryptionKeyChoices keyType, PublicKey encPubKey){
		EncryptionKey encKey = null;
		if(encPubKey != null){
			encKey = new EncryptionKey(new PublicEncryptionKey(SymmAlgorithm.aes128Ccm, new BasePublicEncryptionKey(keyType, cryptoManager.encodeEccPoint(keyType, EccP256CurvePointChoices.compressedy0, encPubKey))))
		}
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,encKey,null,null)
		
		Ieee1609Dot2Data sd = sdg.genSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.HASH_ONLY,certChain, privateKey)
	}
	
}
