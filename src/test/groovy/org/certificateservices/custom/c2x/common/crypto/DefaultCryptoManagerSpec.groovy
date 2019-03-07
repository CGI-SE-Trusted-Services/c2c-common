/************************************************************************
 *                                                                       *
t *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.common.crypto

import com.sun.crypto.provider.AESKeyGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec

import javax.crypto.spec.SecretKeySpec
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECParameterSpec

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*
import static org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm.*

import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.common.crypto.InvalidSignatureException;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.UncompressedEccPoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo
import org.certificateservices.custom.c2x.its.datastructs.msg.EciesNistP256EncryptedKey
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType
import org.certificateservices.custom.c2x.its.datastructs.msg.MessageType
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType
import org.certificateservices.custom.c2x.its.datastructs.msg.RecipientInfo
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerField
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator
import org.certificateservices.custom.c2x.its.generator.AuthorizationTicketCertGenerator
import org.certificateservices.custom.c2x.its.generator.SecuredMessageGenerator;

import spock.lang.Ignore;
import spock.lang.IgnoreRest;
import spock.lang.Shared
import spock.lang.Unroll

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DefaultCryptoManagerSpec extends BaseStructSpec {
	
	@Shared DefaultCryptoManager defaultCryptoManager = new DefaultCryptoManager()
	@Shared KeyPairGenerator sunKeyGenerator = KeyPairGenerator.getInstance("EC", "SunEC")
	
	@Shared KeyPair testSignatureKeys
	@Shared KeyPair testEncKeys
	@Shared Certificate authTicket
	
	@Shared KeyPair altTestSignatureKeys
	@Shared KeyPair altTestEncKeys
	@Shared Certificate altAuthTicket

	def setupSpec(){		
		
		def subParamSpec
		try{
			subParamSpec = sun.security.ec.NamedCurve.getECParameterSpec("secp256r1")
		}catch(MissingMethodException e){
		    subParamSpec  = sun.security.util.ECUtil.getECParameterSpec(null, "secp256r1") 
		}
		sunKeyGenerator.initialize(subParamSpec, new SecureRandom())
		
		defaultCryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		testSignatureKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		testEncKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		altTestSignatureKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		altTestEncKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		
		KeyPair rootCAKeys =  defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		KeyPair authCAKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		
		AuthorityCertGenerator acg = new AuthorityCertGenerator(defaultCryptoManager)

		Certificate rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testSignatureKeys.getPublic(), testSignatureKeys.getPrivate(), null, null)
		Certificate authCA = acg.genAuthorizationAuthorityCA("TestAuthorizationAuthority".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417636852024L), new Date(1417636952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authCAKeys.getPublic(), null, null, rootCAKeys.getPrivate(), rootCA)
		AuthorizationTicketCertGenerator atg = new AuthorizationTicketCertGenerator(defaultCryptoManager, authCA, authCAKeys.privateKey);
		authTicket = atg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testSignatureKeys.getPublic(), PublicKeyAlgorithm.ecies_nistp256, testEncKeys.getPublic())
		altAuthTicket = atg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(12334), new BigInteger(23435)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, altTestSignatureKeys.getPublic(), PublicKeyAlgorithm.ecies_nistp256, altTestEncKeys.getPublic())
	}

	@Unroll
	def "Test to generate ITS ECDSA Signature and then verify the signature for algorithm: #pubAlg"(){
		when:
		byte[] message = "Testmessage".getBytes()
		byte[] invalidMessage = "T1estmessage".getBytes()
		KeyPair keyPair = defaultCryptoManager.generateKeyPair(pubAlg)
		Signature signature = defaultCryptoManager.signMessage(message,
                                     pubAlg, 
									  keyPair.privateKey)
		
				
		then:
		defaultCryptoManager.verifySignature(message, signature, keyPair.getPublic())
		defaultCryptoManager.verifySignature(message, signature, defaultCryptoManager.encodeEccPoint(pubAlg, EccPointType.compressed_lsb_y_0, keyPair.getPublic()))
		!defaultCryptoManager.verifySignature(invalidMessage, signature, keyPair.getPublic())
		
		where:
		pubAlg << [ecdsa_nistp256_with_sha256]
	}
	

	def "Test to verifyCertificate"(){
		expect:
		defaultCryptoManager.verifyCertificate(getTestATCertificate(), getTestAACertificate())
		!defaultCryptoManager.verifyCertificate(getTestATCertificate(), getTestATCertificate())
		defaultCryptoManager.verifyCertificate(getTestATCertificate(), defaultCryptoManager.getVerificationKey(getTestAACertificate()))
		!defaultCryptoManager.verifyCertificate(getTestATCertificate(), defaultCryptoManager.getVerificationKey(getTestATCertificate()))
		defaultCryptoManager.verifyCertificate(getTestATCertificate(), defaultCryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, defaultCryptoManager.getVerificationKey(getTestAACertificate())))
		!defaultCryptoManager.verifyCertificate(getTestATCertificate(), defaultCryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, defaultCryptoManager.getVerificationKey(getTestATCertificate())))
		defaultCryptoManager.verifyCertificate(getTestRootCertificate())

	}
	
	@Unroll
	def "verify that generateKeyPair generates new keypairs for algorithm: #pubAlg"(){
		when:
		KeyPair k1 = defaultCryptoManager.generateKeyPair(pubAlg)
		KeyPair k2 = defaultCryptoManager.generateKeyPair(pubAlg)
		then:
		k1 != k2
		k1 != null
		where:
		pubAlg << [ecdsa_nistp256_with_sha256, ecies_nistp256, BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1,
			PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	BigInteger pubKey1_x = new BigInteger(Hex.decode("00a43331f54d41100588dc349007d0dde48e92cdb4dcdf5d44cef4d452edff76c8"));
	BigInteger pubKey1_y = new BigInteger(Hex.decode("00e0669020eef723207984e7a701ca84108ccebbfcabf307c5a2fa976b8e623d0e"));
	
	
	BigInteger pubKey2_x = new BigInteger(Hex.decode("0053dd6e40e9dccbae817070384ed7668ca8f6932c89597203532d42845049a407"));
	BigInteger pubKey2_y = new BigInteger(Hex.decode("00995938e3fadb175ef8e31c3d74a9875d74a2655a5c419e776f665aee10595a38"));
		

	@Unroll 
	def "Verify that ITS encodeEccPoint encodes ec public keys properly for algorithm: #pubAlg"(){
		when:
		EccPoint p1 = defaultCryptoManager.encodeEccPoint(pubAlg, EccPointType.x_coordinate_only, constructKey(pubKey1_x, pubKey1_y))
		then:
		p1.publicKeyAlgorithm == pubAlg
		p1.eccPointType == x_coordinate_only
		p1.x == pubKey1_x;
		when:
		EccPoint p2 = defaultCryptoManager.encodeEccPoint(pubAlg, EccPointType.compressed_lsb_y_0, constructKey(pubKey1_x, pubKey1_y))		
		then:
		p2.publicKeyAlgorithm == pubAlg
		p2.eccPointType == compressed_lsb_y_0 || p2.eccPointType == compressed_lsb_y_1
		p2.compressedEncoding != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineY() == pubKey1_y
		
		
		when:
		EccPoint p3 = defaultCryptoManager.encodeEccPoint(pubAlg, EccPointType.compressed_lsb_y_0, constructKey(pubKey1_x, pubKey1_y))
		then:
		p3.publicKeyAlgorithm == pubAlg
		p3.eccPointType == compressed_lsb_y_0 || p3.eccPointType == compressed_lsb_y_1
		p3.compressedEncoding != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineY() == pubKey1_y
		
		when:
		EccPoint p4 = defaultCryptoManager.encodeEccPoint(pubAlg, EccPointType.uncompressed, constructKey(pubKey1_x, pubKey1_y))
		then:
		p4.publicKeyAlgorithm == pubAlg
		p4.eccPointType == uncompressed
		p4.x == pubKey1_x
		p4.y == pubKey1_y
		
		where:
		pubAlg << [ecdsa_nistp256_with_sha256, ecies_nistp256]
	}
	

	@Unroll
	def "Verify that decodeEccPoint decodes the EccPoints correctly for public key scheme: #pubAlg"(){
		when: // verify x_coordinate_only
		EccPoint x_onlyPoint = new EccPoint(pubAlg, x_coordinate_only, pubKey1_x)
		Object result = defaultCryptoManager.decodeEccPoint(pubAlg, x_onlyPoint)
		then:
		result instanceof BigInteger
		result == pubKey1_x

		when: // verify compressed_y_lsb_0
		EccPoint compressed_y_lsb_0_point = new EccPoint(pubAlg, Hex.decode("02a43331f54d41100588dc349007d0dde48e92cdb4dcdf5d44cef4d452edff76c8"))
		result = defaultCryptoManager.decodeEccPoint(pubAlg, compressed_y_lsb_0_point)

		then:
		result instanceof ECPublicKey
		result != null
		
		when: // verify compressed_y_lsb_0
		EccPoint compressed_y_lsb_1_point = new EccPoint(pubAlg, Hex.decode("03b14885d818b67c18c48e12e71b504bb4df0eb3d3361d6f3e556eaaa10b72a6ec"))
		result = defaultCryptoManager.decodeEccPoint(pubAlg, compressed_y_lsb_1_point)
				
		then:
		result instanceof ECPublicKey
		result != null
		
		when: // verify compressed_y_lsb_0
		EccPoint uncompressed_point = new EccPoint(pubAlg, uncompressed, pubKey1_x, pubKey1_y)
		result = defaultCryptoManager.decodeEccPoint(pubAlg, compressed_y_lsb_1_point)

		then:
		result instanceof ECPublicKey
		result != null
		
		where:
		pubAlg << [ecdsa_nistp256_with_sha256, ecies_nistp256]      
	}
	
	
	@Unroll
	def "Verify that ieee encodeEccPoint encodes ec public keys properly for algorithm: #pubAlg"(){
		setup:
		ECPublicKey pubKey1 = defaultCryptoManager.generateKeyPair(pubAlg).getPublic()
		BigInteger pubKey1_x = pubKey1.getW().getAffineX()
		BigInteger pubKey1_y = pubKey1.getW().getAffineY()
		when:
		EccP256CurvePoint p1 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.xonly, constructKey(pubKey1_x, pubKey1_y))
		then:
		p1.getChoice() == EccP256CurvePointChoices.xonly
		((COEROctetStream) p1.getValue()).getData() == EccP256CurvePoint.fromBigInteger(pubKey1_x);
		when:
		EccP256CurvePoint p2 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.compressedy0, constructKey(pubKey1_x, pubKey1_y))
		then:
		p2.getChoice() == EccP256CurvePointChoices.compressedy1 || p2.getChoice() == EccP256CurvePointChoices.compressedy0
		((COEROctetStream) p2.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineY() == pubKey1_y
		
		
		when:
		EccP256CurvePoint p3 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.compressedy1, constructKey(pubKey1_x, pubKey1_y))
		then:
		p3.getChoice() == EccP256CurvePointChoices.compressedy1 || p3.getChoice() == EccP256CurvePointChoices.compressedy0
		((COEROctetStream) p3.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineY() == pubKey1_y
		
		when:
		EccP256CurvePoint p4 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.uncompressed, constructKey(pubKey1_x, pubKey1_y))
		UncompressedEccPoint uec = p4.value
		then:
		p4.getChoice() == EccP256CurvePointChoices.uncompressed
		new BigInteger(1,uec.getX()) == pubKey1_x
		new BigInteger(1,uec.getY()) == pubKey1_y
		
		where:
		pubAlg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that decodeEccPoint decodes the ieee EccPoints correctly for public key scheme: #pubAlg"(){
		setup:
		BCECPublicKey pubKey1 = defaultCryptoManager.generateKeyPair(pubAlg).getPublic()
		BigInteger pubKey1_x = pubKey1.getW().getAffineX()
		BigInteger pubKey1_y = pubKey1.getW().getAffineY()
		when: // verify x_coordinate_only
		EccP256CurvePoint x_onlyPoint = new EccP256CurvePoint(pubKey1_x)
		Object result = defaultCryptoManager.decodeEccPoint(pubAlg, x_onlyPoint)
		then:
		result instanceof BigInteger
		result == pubKey1_x

		when: // verify compressed_y
		EccP256CurvePoint compressed_point = new EccP256CurvePoint(pubKey1.getQ().getEncoded(true))
		result = defaultCryptoManager.decodeEccPoint(pubAlg, compressed_point)

		then:
		result instanceof ECPublicKey
		result != null
				
		when: // verify uncompressed_point
		EccP256CurvePoint uncompressed_point = new EccP256CurvePoint(pubKey1.getW().getAffineX(),pubKey1.getW().getAffineY())
		result = defaultCryptoManager.decodeEccPoint(pubAlg, uncompressed_point)

		then:
		result instanceof ECPublicKey
		result != null
		
		where:
		pubAlg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify digest generates a correct digest for algorithm: #alg"(){
		setup:
		def algIndicator = [ getAlgorithm : { new Algorithm(null,null,null, alg)}] as AlgorithmIndicator
		expect:
		  new String(Hex.encode(defaultCryptoManager.digest(message.getBytes(),algIndicator))) == digest
		where:
		alg          | message      | digest
		Hash.sha256  | "abc1234"    | "36f583dd16f4e1e201eb1e6f6d8e35a2ccb3bbe2658de46b4ffae7b0e9ed872e"
		Hash.sha384  | "abc1234"    | "3e742be1e90f0023371e6c4b4b80716715f483a9451218bf14c317370d947719633628af4d8dde3f8d16846edc29ca50"

	}
		
	def "Verify getVerificationKey"(){
		expect:
		defaultCryptoManager.getVerificationKey(getTestAACertificate()) != null
		defaultCryptoManager.getVerificationKey(getTestAACertificate()) instanceof EccPoint
		defaultCryptoManager.getVerificationKey(getTestATCertificate()) != null
		defaultCryptoManager.getVerificationKey(getTestATCertificate()) instanceof EccPoint
		when:
		defaultCryptoManager.getVerificationKey(new Certificate(new ArrayList<?>(), new SubjectInfo(), new ArrayList<?>(), new ArrayList<?>()))
		then:
		thrown IllegalArgumentException
	}
	

	def "Verify getEncryptionKey"(){
		expect:
		defaultCryptoManager.getEncryptionKey(getTestATCertificate()) != null
		defaultCryptoManager.getEncryptionKey(getTestATCertificate()).getPublicKeyAlgorithm() == PublicKeyAlgorithm.ecies_nistp256
		when:
		defaultCryptoManager.getVerificationKey(new Certificate(new ArrayList<?>(), new SubjectInfo(), new ArrayList<?>(), new ArrayList<?>()))
		then:
		thrown IllegalArgumentException
	}
	
	
	def "Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly"(){
		expect:
		new String(Hex.encode(defaultCryptoManager.serializeCertWithoutSignature(getTestAACertificate()))) == "0201ac50a61acf58df6e021354657374417574686f72697a6174696f6e434128000002cd6f09f4696712a254d4f29a9a0a500f678ed549eddb4f8e04979777cb54777d022020017f0901148a82bb27565eab"
		new String(Hex.encode(defaultCryptoManager.serializeCertWithoutSignature(getTestATCertificate()))) == "020115fbb923af7faed701004c0000035359dc6e4d6a5301f01f6a6853a54aef637c7131fa3f37a0e9144ad14ea2c2f1010100038f598ce6d4920494f1fa91e4a4c04889a2a50f7c7a983db4267c1e6d1b38a565022020017f0901170b0de5170b7e65"
	}
	
	def "Verify that getECCurve returns correct curve"(){
		expect:
		defaultCryptoManager.getECCurve(ecdsa_nistp256_with_sha256).q == new BigInteger(1,Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"))
		defaultCryptoManager.getECCurve(ecies_nistp256).q == new BigInteger(1,Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"))
	}
	
	@Unroll
	def "Verify that getECCurve getECParameterSpec returns curve with name: #name for public key algorithm: #pubAlg"(){
		expect:
		defaultCryptoManager.getECParameterSpec(pubAlg).name == name
		where:
		pubAlg                                          | name
		ecdsa_nistp256_with_sha256                      | "P-256"
		ecies_nistp256                                  | "P-256"
	}
	
	def "Verify that convertECPublicKeyToBCECPublicKey supports both BC and SUN Public keys"(){
		expect:
		defaultCryptoManager.toBCECPublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, 
			defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256).publicKey) instanceof BCECPublicKey
		defaultCryptoManager.toBCECPublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,
			sunKeyGenerator.generateKeyPair().publicKey) instanceof BCECPublicKey
		
	}
	
	@Unroll
	def "Verify calculateSignatureLength for public algorithm #pubAlg and R EccPointType #eccPointType"(){
		setup:
		EcdsaSignature ecsig = new EcdsaSignature(pubAlg)
		ecsig.r = new EccPoint(pubAlg)
		ecsig.r.eccPointType = eccPointType
		Signature signature = new Signature(pubAlg,ecsig)
		signature.publicKeyAlgorithm = pubAlg
		expect:
		defaultCryptoManager.calculateSignatureLength(signature) == signature_size
		where:
		pubAlg                        | eccPointType        | signature_size
		ecdsa_nistp256_with_sha256    | x_coordinate_only   | 67
		ecdsa_nistp256_with_sha256    | compressed_lsb_y_1  | 67
		ecdsa_nistp256_with_sha256    | compressed_lsb_y_0  | 67
		ecdsa_nistp256_with_sha256    | uncompressed        | 99
	}
	
	def "Verify calculateSignatureLength throws exception for #pubAlg"(){
		setup:
		Signature signature = new Signature()
		signature.publicKeyAlgorithm = pubAlg
		when:
		defaultCryptoManager.calculateSignatureLength(signature)
		then:
		thrown IllegalArgumentException 
		where:
		pubAlg << [ecies_nistp256]
	}
	
	static sig_x_only = new Signature(ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]))
	static sig_compressed_y_1 = new Signature(ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_1, new BigInteger(1)), new byte[32]))
	static sig_compressed_y_0 = new Signature(ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_0, new BigInteger(1)), new byte[32]))
	static sig_uncompressed  = new Signature(ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, new BigInteger(1),new BigInteger(2)), new byte[32]))
	@Unroll
	def "Verify serializeTotalSignedTrailerLength calculates signature trailing fields correctly #description"(){
		setup:
		def baos = new ByteArrayOutputStream()
		def dos = new DataOutputStream(baos)
		when: "Test with no signature trailer field"
		defaultCryptoManager.serializeTotalSignedTrailerLength(dos, trailerFields, signature)
		String result = new String(Hex.encode(baos.toByteArray()))
		then:
		result == expectedValue 
		where:
        description                                                  | expectedValue | trailerFields                                | signature
		"no signature trailer field"                                 | "43"          | []                						    | sig_x_only
		"signature trailer field with x_coordinate_only ecc point"   | "43"          | [new TrailerField(sig_x_only)]               | sig_x_only
		"signature trailer field with compressed_lsb_y_1 ecc point"  | "43"          | [new TrailerField(sig_compressed_y_1)]       | sig_compressed_y_1
		"signature trailer field with compressed_lsb_y_0 ecc point"  | "43"          | [new TrailerField(sig_compressed_y_0)]       | sig_compressed_y_0
		"signature trailer field with uncompressed ecc point"        | "63"          | [new TrailerField(sig_uncompressed)]         | sig_uncompressed
	}
	
	static payload_signed = new Payload(PayloadType.signed, new byte[32]);
	static payload_unsecured = new Payload(PayloadType.unsecured, new byte[16]);
	static payload_encrypted = new Payload(PayloadType.encrypted, new byte[48]);
	static payload_signed_and_encrypted = new Payload(PayloadType.signed_and_encrypted, new byte[80]);
	static payload_signed_external = new Payload(PayloadType.signed_external, new byte[80]);
	
	def "Verify serializeTotalPayload calculates signature payload fields correctly"(){
		setup:
		def baos = new ByteArrayOutputStream()
		def dos = new DataOutputStream(baos)
		when: "Test with no signature trailer field"
		defaultCryptoManager.serializeTotalPayloadSize(dos, [payload_signed,payload_unsecured,payload_signed_and_encrypted])
		String result = new String(Hex.encode(baos.toByteArray()))
		then:
		result == "8086"
		
	}
	
	def "Verify findSignatureInMessage throws exception if no signature element was found."(){
		when:
		defaultCryptoManager.findSignatureInMessage(new SecuredMessage())
		then:
		thrown IllegalArgumentException
		when:
		defaultCryptoManager.findSignatureInMessage(new SecuredMessage(1,2,[],[],[]))		
		then:
		thrown IllegalArgumentException
		
	}
	
	def "Verify findSignatureInMessage returns first found signature trailer field"(){		
		expect:
		defaultCryptoManager.findSignatureInMessage(new SecuredMessage(1,2,[],[],[new TrailerField(sig_x_only)])) == sig_x_only		
	}
	
	def "Verify that serializeDataToBeSignedInSecuredMessage serializes according to signature verification it ETSI specifification"(){
		setup:
		SecuredMessage sm = new SecuredMessage([new HeaderField(2,new Time32(1000)),new HeaderField(2, new IntX(123))],new Payload(PayloadType.signed, Hex.decode("01020304")))
		EcdsaSignature ecsig = new EcdsaSignature(ecdsa_nistp256_with_sha256)
		ecsig.r = new EccPoint(ecdsa_nistp256_with_sha256)
		ecsig.r.eccPointType = EccPointType.x_coordinate_only
		Signature signature = new Signature(ecdsa_nistp256_with_sha256,ecsig)
		signature.publicKeyAlgorithm = ecdsa_nistp256_with_sha256
		when:
		def result = new String(Hex.encode(defaultCryptoManager.serializeDataToBeSignedInSecuredMessage(sm, signature)));
		then:    // version,  header length,  expiration, expiration value, message type, itsaid,   payload signed + length, data        trailer field length (66)  trailer field signature
		result == "02"        +  "07"           + "02"      + "000003e8"     + "05"         + "7b"   +  "01" +  "04" + "01020304" + "43"                       + "01";
	}
	

	@Unroll
	def "Verify SignSecuredMessage using signer info type: #signInfoType generates a valid signature and that verifySecuredMessage can verify it."(){
		
		when:
		SecuredMessage sm = defaultCryptoManager.signSecureMessage(genSecuredMessage(SignerInfoType.certificate, authTicket, Hex.decode("4321")), authTicket, null, signInfoType ,PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testSignatureKeys.getPrivate())
		byte[] messageData = sm.encoded
		then:
		sm.getTrailerFields().size() == 1
		when:
		SecuredMessage verifySm = new SecuredMessage(messageData)
		then:
		if(signInfoType == SignerInfoType.certificate){
		  defaultCryptoManager.verifySecuredMessage(verifySm)
		}else{
		  defaultCryptoManager.verifySecuredMessage(verifySm, authTicket) 
		}
		when:
		// check that invalid certificate is false
		!defaultCryptoManager.verifySecuredMessage(verifySm, testATCertificate)
		then:
		thrown InvalidSignatureException
		where:
		signInfoType << [SignerInfoType.certificate, SignerInfoType.certificate_digest_with_ecdsap256]
		
	}
	

	
	
	def "Verify that eCEISEncryptSymmetricKey and eCEISDecryptSymmetricKey encrypts and decrypts symmetric key correcly."(){
		setup:
		KeyGenerator kgen = KeyGenerator.getInstance("AES","BC")
		kgen.init(128)
		SecretKey key = kgen.generateKey()
		KeyPair kp = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		when:
		def ecies = defaultCryptoManager.itsEceisEncryptSymmetricKeyVer2(PublicKeyAlgorithm.ecies_nistp256, kp.getPublic(), key)
		then:
		ecies.v != null
		ecies.c != null
		ecies.t != null
		when:
		SecretKey decryptedKey = defaultCryptoManager.itsEciesDecryptSymmetricKeyVer2(ecies, kp.getPrivate())
		then:
		key.getEncoded() == decryptedKey.getEncoded()
	}


	static byte[] testVector_D6_2_1_emperical_privateKey_deviation = Hex.decode("1384C31D6982D52BCA3BED8A7E60F52F")
	static byte[] testVector_D6_2_1_emperical_privateKey_encoding = Hex.decode("ECDAB44E5C0EA166815A8159E09FFB42")
	static String testVector_D6_2_1_recipient_privateKey = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
	static byte[] testVector_D6_2_1_recipient_publicKey_x = Hex.decode("8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11")
	static byte[] testVector_D6_2_1_recipient_publicKey_y = Hex.decode("1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E")
	static byte[] testVector_D6_2_1_symKey = Hex.decode("9169155B08B07674CBADF75FB46A7B0D")
	static byte[] testVector_D6_2_1_recipientHash = Hex.decode("9169155B08B07674CBADF75FB46A7B0D")

	def "Verify that test vector of IEEE 1609.2 2017 amendment is correct"(){
		setup:
		SecretKey aesKey = new SecretKeySpec(testVector_D6_2_1_symKey, "AES")
		org.bouncycastle.jce.spec.ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256")
        org.bouncycastle.jce.spec.ECPrivateKeySpec recipientPrivateKeySpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(testVector_D6_2_1_recipient_privateKey,16), ecNistP256Spec)
		//org.bouncycastle.jce.spec.ECPrivateKeySpec empericalPrivateKeySpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(testVector_D6_2_1_emperical_privateKey,16), ecNistP256Spec)
		KeyFactory kf = KeyFactory.getInstance("EC", "BC")
		ECPrivateKey recipientPrivateKey = kf.generatePrivate(recipientPrivateKeySpec)
		//ECPrivateKey empericalPrivateKey = kf.generatePrivate(empericalPrivateKeySpec)
		EccP256CurvePoint uncompressed_point = new EccP256CurvePoint(testVector_D6_2_1_recipient_publicKey_x,testVector_D6_2_1_recipient_publicKey_y)
		ECPublicKey recipientPublicKey = defaultCryptoManager.decodeEccPoint(PublicVerificationKeyChoices.ecdsaNistP256, uncompressed_point)


		when:
		def ecies = defaultCryptoManager.itsEceisEncryptSymmetricKeyVer2(PublicKeyAlgorithm.ecies_nistp256, recipientPublicKey, aesKey, testVector_D6_2_1_emperical_privateKey_deviation,testVector_D6_2_1_emperical_privateKey_encoding,null)
		then:
		println Hex.toHexString(ecies.c)
	}



	def "Verify that symmetric encrypt and decrypt works for aes_128_ccm"(){
		setup:
		KeyGenerator kgen = KeyGenerator.getInstance("AES","BC");
		kgen.init(128);
		SecretKey key = kgen.generateKey();
		SecureRandom random = new SecureRandom();
		byte[] nounce = new byte[12];
		random.nextBytes(nounce);
		int dataSize = random.nextInt(10000);
		
		byte[] data = new byte[dataSize]
		random.nextBytes(data);
		
		when:
		byte[] encryptedData = defaultCryptoManager.symmetricEncrypt(SymmetricAlgorithm.aes_128_ccm, data, key, nounce)
		byte[] decryptedData = defaultCryptoManager.symmetricDecrypt(SymmetricAlgorithm.aes_128_ccm, encryptedData, key, nounce)
		then:
		encryptedData != data
		decryptedData == data
	}
	
	def "verify that encryptSecureMessage and decryptSecureMessage encrypts and decrypts correctly"(){
		setup:
		SecuredMessage sm = new SecuredMessage([new HeaderField(2,new Time64(10000000000L))],new Payload(PayloadType.encrypted, "Encrypt1".getBytes("UTF-8")))
		when:
		SecuredMessage esm = defaultCryptoManager.encryptSecureMessage(sm, PublicKeyAlgorithm.ecies_nistp256, [authTicket,altAuthTicket])
		then: "Verify that encrypt adds the correct headers and encrypts values"
		esm.headerFields.size() == 3
		esm.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		esm.headerFields[1].headerFieldType == HeaderFieldType.encryption_parameters
		esm.headerFields[2].headerFieldType == HeaderFieldType.recipient_info
		
		esm.payloadFields.size() == 1
		esm.payloadFields[0].payloadType == PayloadType.encrypted
		new String(esm.payloadFields[0].getData(),"UTF-8") != "Encrypt1"
		
		when:
		SecuredMessage dsm = defaultCryptoManager.decryptSecureMessage(esm, authTicket, testEncKeys.privateKey)
		then:
		dsm.headerFields.size() == 3
		dsm.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		dsm.headerFields[1].headerFieldType == HeaderFieldType.encryption_parameters
		dsm.headerFields[2].headerFieldType == HeaderFieldType.recipient_info
		
		dsm.payloadFields.size() == 1
		dsm.payloadFields[0].payloadType == PayloadType.encrypted
		new String(dsm.payloadFields[0].getData(),"UTF-8") == "Encrypt1"
		
		when: "Verify that alternate reveiptient also can decrypt"
		SecuredMessage dsm2 = defaultCryptoManager.decryptSecureMessage(esm, altAuthTicket, altTestEncKeys.privateKey)
		then:
		dsm2.headerFields.size() == 3
		dsm2.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		dsm2.headerFields[1].headerFieldType == HeaderFieldType.encryption_parameters
		dsm2.headerFields[2].headerFieldType == HeaderFieldType.recipient_info
		
		dsm2.payloadFields.size() == 1
		dsm2.payloadFields[0].payloadType == PayloadType.encrypted
		new String(dsm2.payloadFields[0].getData(),"UTF-8") == "Encrypt1"

		
		when: "Verify that decrypting message without proper headers throws IllegalArgumentException"
		defaultCryptoManager.decryptSecureMessage(sm, altAuthTicket, altTestEncKeys.privateKey)
		then:
		thrown IllegalArgumentException
		
		when: "Verify that decrypting a message without being on the receiptent list throws IllegalArgumentException"
		SecuredMessage esm2 = defaultCryptoManager.encryptSecureMessage(sm,  PublicKeyAlgorithm.ecies_nistp256, [authTicket])
		defaultCryptoManager.decryptSecureMessage(esm2, altAuthTicket, altTestEncKeys.privateKey)
		then:
		thrown IllegalArgumentException
		
		when: "Verify that decrypting a message with faulty private key throws IllegalArgumentException"
		defaultCryptoManager.decryptSecureMessage(esm2, authTicket, altTestEncKeys.privateKey)
		then:
		thrown GeneralSecurityException
	}
	

	def "Verify that signAndEncryptSecureMessage and verifyAndDecryptSecuredMessage both encrypts and signs properly"(){
	  setup:
	  SecuredMessage sm = genSecuredMessage(SignerInfoType.certificate, authTicket, "4321".getBytes("UTF-8"), PayloadType.signed_and_encrypted)
	  
	  when: "Try to encrypt and sign a message"
	  SecuredMessage esm = defaultCryptoManager.encryptAndSignSecureMessage(sm, authTicket, null,SignerInfoType.certificate, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testSignatureKeys.getPrivate(), PublicKeyAlgorithm.ecies_nistp256, [authTicket,altAuthTicket])
	  then:"Verify signature, that content is encrypted and that correct header fields have been set."
	  defaultCryptoManager.verifySecuredMessage(esm)
	  esm.payloadFields.size() == 1
	  new String(esm.payloadFields[0].data,"UTF-8") != "4321"
	  esm.headerFields.size() == 5
	  esm.headerFields[0].headerFieldType == HeaderFieldType.signer_info
	  esm.headerFields[1].headerFieldType == HeaderFieldType.generation_time
	  esm.headerFields[2].headerFieldType == HeaderFieldType.its_aid
	  esm.headerFields[3].headerFieldType == HeaderFieldType.encryption_parameters
	  esm.headerFields[4].headerFieldType == HeaderFieldType.recipient_info
	  
	  when: "Decrypt and verify message"
	  SecuredMessage dsm = defaultCryptoManager.verifyAndDecryptSecuredMessage(esm, authTicket, testEncKeys.privateKey)
	  then:
	  dsm.payloadFields.size() == 1
	  new String(dsm.payloadFields[0].data,"UTF-8") == "4321"
	  when: "Decrypt and verify when signing certificate is specified"
	  SecuredMessage dsm2 = defaultCryptoManager.verifyAndDecryptSecuredMessage(esm, authTicket, authTicket, testEncKeys.privateKey)
	  then:
	  dsm2.payloadFields.size() == 1
	  new String(dsm2.payloadFields[0].data,"UTF-8") == "4321"
	  when: "Verify that corrupt message data throws InvalidITSSignatureException"
	  esm.payloadFields[0].data = "CorruptData"
	  defaultCryptoManager.verifyAndDecryptSecuredMessage(esm, authTicket, testEncKeys.privateKey)
	  then:
	  thrown InvalidSignatureException
	}
	
	

	def "Verify that addHeader adds the header value in correct order"(){
		setup:
		SecuredMessage sm = new SecuredMessage([], new Payload(PayloadType.unsecured,new byte[0]))
		
		when: "Verify that empty header value just inserts it"
		defaultCryptoManager.addHeader(sm, new HeaderField(2,new Time64(2,new Date(10000000000000L))))
		then:
		sm.headerFields.size() == 1
		sm.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		defaultCryptoManager.addHeader(sm, new HeaderField(2,new Time32(2,new Date(10000000000000L))))
		when: "If type value is in the middle it is inserted in the correct location"
		
		defaultCryptoManager.addHeader(sm, new HeaderField(2,new Time64WithStandardDeviation(new Time64(2,new Date(10000000000000L)), 2)))
		then:
		sm.headerFields.size() == 3
		sm.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		sm.headerFields[1].headerFieldType == HeaderFieldType.generation_time_confidence
		sm.headerFields[2].headerFieldType == HeaderFieldType.expiration
		
		when: "If it should be at the end of the list it is appended"
		defaultCryptoManager.addHeader(sm, new HeaderField(2,new IntX(123)))
		then:
		sm.headerFields.size() == 4
		sm.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		sm.headerFields[1].headerFieldType == HeaderFieldType.generation_time_confidence
		sm.headerFields[2].headerFieldType == HeaderFieldType.expiration
		sm.headerFields[3].headerFieldType == HeaderFieldType.its_aid
		
	}
	
	def "Verify that findHeader finds the correct header in a SecureMessage"(){
		setup:
		SecuredMessage sm = new SecuredMessage([new HeaderField(2,new Time64(2,new Date(10000000000000L))),
			new HeaderField(2,new Time64WithStandardDeviation(new Time64(2,new Date(10000000000000L)), 2)),
			new HeaderField(2,new Time32(2,new Date(10000000000000L)))], new Payload(PayloadType.unsecured, new byte[0]))
		
		when: "Verify that correct header value is found."
		HeaderField h1 = defaultCryptoManager.findHeader(sm, HeaderFieldType.generation_time, false)
		HeaderField h2 = defaultCryptoManager.findHeader(sm, HeaderFieldType.generation_time_confidence, true)
		HeaderField h3 = defaultCryptoManager.findHeader(sm, HeaderFieldType.expiration, false)
		then:
		h1.headerFieldType == HeaderFieldType.generation_time
		h2.headerFieldType == HeaderFieldType.generation_time_confidence
		h3.headerFieldType == HeaderFieldType.expiration
		when: "Verify that IllegalArgumentException is thrown for required header fields."
		defaultCryptoManager.findHeader(sm, HeaderFieldType.message_type, true)
		then:
		thrown IllegalArgumentException
		expect: "Verify that null is return for non required non-existing fields."
		defaultCryptoManager.findHeader(sm, HeaderFieldType.message_type, false) == null
		
	}
	
	def "Verify that findRecipientInfo find correct RecipientInfo"(){
		setup:
		HashedId8 rootHashId = new HashedId8(getTestRootCertificate().getEncoded())
		def keyInfo = new EciesNistP256EncryptedKey(2,PublicKeyAlgorithm.ecies_nistp256)
		def rInfos = [new RecipientInfo(new HashedId8(getTestRootCertificate().getEncoded()), keyInfo),
			new RecipientInfo(new HashedId8(getTestAACertificate().getEncoded()), keyInfo),
			new RecipientInfo(new HashedId8(getTestATCertificate().getEncoded()), keyInfo)]
		when:
		RecipientInfo ri = defaultCryptoManager.findRecipientInfo(getTestRootCertificate(), rInfos)
		then:
		ri.getCertId() == rootHashId
		
		when: "Verify that IllegalArgumentException is thrown if not found"
		defaultCryptoManager.findRecipientInfo(authTicket, rInfos)
		then:
		thrown(IllegalArgumentException)
	}
	
	
	def "Verify signature of reference secure messages from interoperabiltity site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/"(){
		expect:
		defaultCryptoManager.verifySecuredMessage(new SecuredMessage(externalSecureMessage1))
		defaultCryptoManager.verifySecuredMessage(new SecuredMessage(externalSecureMessage2))
		defaultCryptoManager.verifySecuredMessage(new SecuredMessage(externalSecureMessage3))
	}
	
	def "Verify that getSignatureChoice returns #sigChoice for alg #sigAlg"(){
		expect:
		defaultCryptoManager.getSignatureChoice(sigAlg) == sigChoice
		where:
		sigChoice                                      | sigAlg
		SignatureChoices.ecdsaNistP256Signature        | Algorithm.Signature.ecdsaNistP256
		SignatureChoices.ecdsaBrainpoolP256r1Signature | Algorithm.Signature.ecdsaBrainpoolP256r1
	}

	static final def externalSecureMessage1 = Hex.decode("010181038002010901A8ED6DF65B0E6D6A0100809400000418929DB6A9E452223062C52028E956BF9874E0A40D21D5F9F56564F39C5DD187C922F2E5F0630373879A43393373B9F6205BF01FBD9C1F113165C291C376F535010004EABA91A915D81807E910FD292D99DF8B401EED88CF7F031412D5ED9905F9996469798C412FC8F7237A3AB3469795E2DEF5E1B783EA4F6B6A2359D21772B2EA9D0200210AC040800101C0408101010F01099EB20109B1270003040100960000004B2E6D0D0EE9BC4AD9CD087B601E9AF06031995443D652763455FBB794B33982889260740EF64CFA8C6808A58F98E06CE42A1E9C22A0785D7242647F7895ABFC0000009373931CD7580500021E011C983E690E5F6D755BD4871578A9427E7BC383903DC7DA3B560384013643010000FE8566BEA87B39E6411F80226E792D6E01E77B598F2BB1FCE7F2DD441185C07CEF0573FBFB9876B99FE811486F6F5D499E6114FC0724A67F8D71D2A897A7EB34")
	static final def externalSecureMessage2 = Hex.decode("010181038002010901A8ED6DF65B0E6D6A01008094000004C4EC137145DD4F450145DE530CCA36E73AB3D87FC8275847CDAD8248C1CD20879BD6A8CB54EA9E05D3B41376CE2F24789AEF82836CA818D568ADF4A140E96E48010004D6C268EE68B5B8B387B2312B7E1D21CE0C366D251A32431508B96EB6A3479CCF96A8738F30ED451F00DA8DDE84367C7EB16727D14FF14F5DD8F9791FE0A12A640200210AC040800101C0408101010F01099EB20109B1270003040100960000001EB035FE8E51DCDD8558DE0BE9B87895B36B420583A5C6B2B8B2EAB7F3D3C99163638FA025A0033D4BD80BBA02B8E3DE1B55766459D494677AF24917E51B80AC0000009373CC5F22C8050002220120F29384759027349075829034707ABABABABABAABAB98437985739845783974954301000081E7CDB6D2C741C1700822305C39E8E809622AF9FCA1C0786F762D08E80580C42F1FCC1D5499577210834C390BB4613E102DECB14F575A2820743DC9A66BBD7A")
	static final def externalSecureMessage3 = Hex.decode("010181038002010901A8ED6DF65B0E6D6A010080940000040209B0434163CCBAFDD34A45333E418FB96C05BBE0E7E1D755D40D0B4BBE8DA508EC2F2723B7ADF0F27C39F3AECFF0783C196F9961F8821E6294375D9294CD6A01000452113CE698DB081491675DF8FFE81C23EA5D0071B2D2BF0E0DA4ADA0CDA58259CA5D999200B6565E194EDAB8BD3DCA863F2DDF39C13E7A0375ECE2566C5EB8C60200210AC040800101C0408101010F01099EB20109B1270003040100960000008DA1F3F9F35E04C3DE77D7438988A8D57EBE44DAA021A4269E297C177C9CFE458E128EC290785D6631961625020943B6D87DAA54919A98F7865709929A7C6E480000009373CF482D400500020A01080123456789ABCDEF43010000371423BBA0902D8AF2FB2226D73A7781D4D6B6772650A8BEE5A1AF198CEDABA2C9BF57540C629E6A1E629B8812AEBDDDBCAF472F6586F16C14B3DEFBE9B6ADB2")
	
	private ECPublicKey constructKey(BigInteger x, BigInteger y){
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec ecParameters = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
        return KeyFactory.getInstance("EC", "SunEC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), ecParameters));
	}
	
	private Certificate getTestRootCertificate(){
		String rootCertOrgString = "0200040a54657374526f6f744341280000031ef2e88fa036fe7bc1a5b19ac18c3b5db36c2148de0b09d646d4a72a19174ea0022020017f0901148a8257275685bb000071bf074aed5db8af658b64a7e6ca66fb1b074d96b913add727f27625d4602487b0815d20cc23340e57d675cb594815638f4f57462a8c713b77f1dfaf1d152e33"
		Certificate cert = deserializeFromHex(new Certificate(),rootCertOrgString);
		return cert;
	}
	
	private Certificate getTestAACertificate(){
		String aaCertOrgString = "0201ac50a61acf58df6e021354657374417574686f72697a6174696f6e434128000002cd6f09f4696712a254d4f29a9a0a500f678ed549eddb4f8e04979777cb54777d022020017f0901148a82bb27565eab0000898804ab8dffc01d55af7bac4ee764e05f4f5c619bb51c3856c7a071d96f2433c07ce44f536f4a1b22dad9043c289670e26c333350f546054fc89e9551b87cd4"
		Certificate cert = deserializeFromHex(new Certificate(),aaCertOrgString);
		return cert;
	}
	
	private Certificate getTestATCertificate(){
		String atCertOrgString = "020115fbb923af7faed701004c0000035359dc6e4d6a5301f01f6a6853a54aef637c7131fa3f37a0e9144ad14ea2c2f1010100038f598ce6d4920494f1fa91e4a4c04889a2a50f7c7a983db4267c1e6d1b38a565022020017f0901170b0de5170b7e65000093e0736bf8a32aa09268aa63b233ccfcf0d785ebd9a002f83af765f86c440bc5aa75e2092f5ff1e7dacc0d42bd5e8b3c42410e6f28ba85820e5c3038c660f66b"
		Certificate cert = deserializeFromHex(new Certificate(),atCertOrgString);
		return cert;
	}
	
	private SecuredMessage genSecuredMessage(SignerInfoType signerInfoType, Certificate senderCertificate, byte[] payLoad, PayloadType payLoadType=PayloadType.signed){
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(senderCertificate.getVersion(),new Time64(senderCertificate.getVersion(),new Date()))); // generate generation time
		headerFields.add(new HeaderField(senderCertificate.getVersion(),new IntX(SecuredMessageGenerator.ITS_AID_CAM)));
		
		Payload pl;
		if(payLoad == null){
			pl = new Payload(payLoadType,new byte[0]);
		}else{
			pl = new Payload(payLoadType,payLoad)
		}
		
		return new SecuredMessage(headerFields, pl);
	}
	
	
}

