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
package org.certificateservices.custom.c2x.its.crypto


import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*
import static org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm.*

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.MessageType;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerField
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator
import org.certificateservices.custom.c2x.its.generator.AuthorizationTicketCertGenerator
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.IgnoreRest;
import spock.lang.Shared
import spock.lang.Unroll

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DefaultCryptoManagerSpec extends BaseStructSpec {
	
	@Shared DefaultCryptoManager defaultCryptoManager = new DefaultCryptoManager();
	@Shared KeyPairGenerator sunKeyGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
	
	@Shared KeyPair testKeys;
	@Shared Certificate authTicket;

	
	def setupSpec(){		
		
		def subParamSpec = sun.security.ec.NamedCurve.getECParameterSpec("secp256r1")
		sunKeyGenerator.initialize(subParamSpec, new SecureRandom());
		
		defaultCryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		testKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		KeyPair rootCAKeys =  defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		KeyPair authCAKeys = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		
		AuthorityCertGenerator acg = new AuthorityCertGenerator(defaultCryptoManager)

		Certificate rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testKeys.getPublic(), testKeys.getPrivate(), null, null)
		Certificate authCA = acg.genAuthorizationAuthorityCA("TestAuthorizationAuthority".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417636852024L), new Date(1417636952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authCAKeys.getPublic(), null, null, rootCAKeys.getPrivate(), rootCA)
		AuthorizationTicketCertGenerator atg = new AuthorizationTicketCertGenerator(defaultCryptoManager, authCA, authCAKeys.privateKey);
		authTicket = atg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testKeys.getPublic(), null, null)
		
	}

	@Unroll
	def "Test to generate ECDSA Signature and then verify the signature for algorithm: #pubAlg"(){
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
		// TODO Test with certificate
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
		// TOOD test cert with signer info cert
		// TODO test cert with signer info cert chain
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
		pubAlg << [ecdsa_nistp256_with_sha256, ecies_nistp256]
	}
	
	BigInteger pubKey1_x = new BigInteger(Hex.decode("00a43331f54d41100588dc349007d0dde48e92cdb4dcdf5d44cef4d452edff76c8"));
	BigInteger pubKey1_y = new BigInteger(Hex.decode("00e0669020eef723207984e7a701ca84108ccebbfcabf307c5a2fa976b8e623d0e"));
	
	
	BigInteger pubKey2_x = new BigInteger(Hex.decode("0053dd6e40e9dccbae817070384ed7668ca8f6932c89597203532d42845049a407"));
	BigInteger pubKey2_y = new BigInteger(Hex.decode("00995938e3fadb175ef8e31c3d74a9875d74a2655a5c419e776f665aee10595a38"));
		

	@Unroll 
	def "Verify that encodeEccPoint encodes ec public keys properly for algorithm: #pubAlg"(){
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
		where:
		pubAlg << [ecdsa_nistp256_with_sha256, ecies_nistp256]      
	}
	
	@Unroll
	def "Verify digest generates a correct digest for algorithm: #pubKeyAlg"(){
		expect:
		  new String(Hex.encode(defaultCryptoManager.digest(message.getBytes(),pubKeyAlg))) == digest
		where:
		pubKeyAlg                   | message      | digest
		ecdsa_nistp256_with_sha256  | "abc1234"    | "36f583dd16f4e1e201eb1e6f6d8e35a2ccb3bbe2658de46b4ffae7b0e9ed872e" 
		
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
	
	def "Verify that serializeCertWithoutSignature encodes the certificate without the signature correcly"(){
		expect:
		new String(Hex.encode(defaultCryptoManager.serializeCertWithoutSignature(getTestAACertificate()))) == "028112020201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f790210455453495f506c7567746573745f41418091000004f4c5e1e8650fef248fb90a38499c11fe8e4a58ed25c368ee36790232e0d770f5619f7174da9629f981f5d365e3eddfe406ffe4920c723dad473a87b5b05ae57f010100045b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe5b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe02202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350"
		new String(Hex.encode(defaultCryptoManager.serializeCertWithoutSignature(getTestATCertificate()))) == "020901bae315dc4e2c97f801008095000004b462520bee11df3cd826e969e4db0ba4327e686e2526fa05bffa617773d217fdca45fb75c453430521484332a0835f5bb690201b1ef3d8fe2c43bdf2eb3865a6010100049f803aaf544262eb522c5ce2332f018cac4d9817b6fddda97d12b01bcdaf56f92bf1ea0b3d0d969cb5d3c1d5fce9eba043d340b76ba7f44e4fc83d6f753517cf0220210ac040800100c040810100240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350"
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
		defaultCryptoManager.convertECPublicKeyToBCECPublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, 
			defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256).publicKey) instanceof BCECPublicKey
		defaultCryptoManager.convertECPublicKeyToBCECPublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,
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
		ecdsa_nistp256_with_sha256    | x_coordinate_only   | 66
		ecdsa_nistp256_with_sha256    | compressed_lsb_y_1  | 66
		ecdsa_nistp256_with_sha256    | compressed_lsb_y_0  | 66
		ecdsa_nistp256_with_sha256    | uncompressed        | 98
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
		"no signature trailer field"                                 | "42"          | []                						    | sig_x_only
		"signature trailer field with x_coordinate_only ecc point"   | "42"          | [new TrailerField(sig_x_only)]               | sig_x_only
		"signature trailer field with compressed_lsb_y_1 ecc point"  | "42"          | [new TrailerField(sig_compressed_y_1)]       | sig_compressed_y_1
		"signature trailer field with compressed_lsb_y_0 ecc point"  | "42"          | [new TrailerField(sig_compressed_y_0)]       | sig_compressed_y_0
		"signature trailer field with uncompressed ecc point"        | "62"          | [new TrailerField(sig_uncompressed)]         | sig_uncompressed
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
		SecuredMessage sm = new SecuredMessage(MessageType.CAM.getSecurityProfile(),[new HeaderField(new Time32(1000)),new HeaderField(MessageType.CAM.getValue())],[new Payload(PayloadType.unsecured, new byte[3]),new Payload(PayloadType.signed, Hex.decode("01020304"))])
		EcdsaSignature ecsig = new EcdsaSignature(ecdsa_nistp256_with_sha256)
		ecsig.r = new EccPoint(ecdsa_nistp256_with_sha256)
		ecsig.r.eccPointType = EccPointType.x_coordinate_only
		Signature signature = new Signature(ecdsa_nistp256_with_sha256,ecsig)
		signature.publicKeyAlgorithm = ecdsa_nistp256_with_sha256
		when:
		def result = new String(Hex.encode(defaultCryptoManager.serializeDataToBeSignedInSecuredMessage(sm, signature)));
		then:    // version,  sec prof, header length,  expiration, expiration value, message type, CAM value, payload length, unsecured, length, signed + length, data        trailer field length (66)
		result == "01"       + "01" +  "08"           + "02"      + "000003e8"     + "05"         + "0002"   + "0b"         + "00"      + "03" +  "01" +  "04" + "01020304" + "42";
	}
	

	@Unroll
	def "Verify SignSecuredMessage using signer info type: #signInfoType generates a valid signature and that verifySecuredMessage can verify it."(){
		
		when:
		SecuredMessage sm = defaultCryptoManager.signSecureMessage(genSecuredMessage(SignerInfoType.certificate, authTicket, Hex.decode("4321")), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, testKeys.getPrivate())
		byte[] messageData = sm.encoded
		then:
		sm.getTrailerFields().size() == 1
		when:
		SecuredMessage verifySm = new SecuredMessage(messageData)
		then:
		if(signInfoType == SignerInfoType.certificate){
		  assert defaultCryptoManager.verifySecuredMessage(verifySm) == true
		}else{
		  assert defaultCryptoManager.verifySecuredMessage(verifySm, authTicket) 
		}
		// check that invalid certificate is false
		!defaultCryptoManager.verifySecuredMessage(verifySm, testATCertificate)
		
		where:
		signInfoType << [SignerInfoType.certificate, SignerInfoType.certificate_digest_with_ecdsap256]
		
	}
	
	
	
	private ECPublicKey constructKey(BigInteger x, BigInteger y){
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec ecParameters = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
        return KeyFactory.getInstance("EC", "SunEC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), ecParameters));
	}
	
	private Certificate getTestRootCertificate(){
		String rootCertOrgString = "0201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f79"
		Certificate cert = deserializeFromHex(new Certificate(),rootCertOrgString);
		return cert;
	}
	
	private Certificate getTestAACertificate(){
		String aaCertOrgString = "028112020201000412455453495f506c7567746573745f526f6f748091000004bf8a03e7a5c26ecc9cde8199ac933b4f934ea2e5555acffd71c81e127ef15a75ed5f95ea1ec498d2bd01974676e7812bbffd0cac6f37db20cf8791e3a458a7d901010004bcdc54771cb782683d4cdeca0853d11600756ace9120b672caba69976b145f6f49a72be0141b8ed085371cb33aa4c2dc2c80aee7448a130d07d38cdda65ca78002202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d005278350000041001bca24d594da442a1e653dd618ccddca435ac6308b53018e881dea14a31e64b7d4da721ef2ff7c67563b4bf16ad79b3288a3878c821dfe394c5484ca7f790210455453495f506c7567746573745f41418091000004f4c5e1e8650fef248fb90a38499c11fe8e4a58ed25c368ee36790232e0d770f5619f7174da9629f981f5d365e3eddfe406ffe4920c723dad473a87b5b05ae57f010100045b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe5b36e9ab76e977f6cb1b822e8bdee82ee72f28f1055128c0051c9f85699abebe02202006c04080c04081240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000be28371f8b18d411581c10f30310128625f78f9c69761757d58203c6c757f38ec10d683159c9a52bc3f3e9563194ccaf694cadac56cbaee575bc7366f02ea09d"
		Certificate cert = deserializeFromHex(new Certificate(),aaCertOrgString);
		return cert;
	}
	
	private Certificate getTestATCertificate(){
		String atCertOrgString = "020901bae315dc4e2c97f801008095000004b462520bee11df3cd826e969e4db0ba4327e686e2526fa05bffa617773d217fdca45fb75c453430521484332a0835f5bb690201b1ef3d8fe2c43bdf2eb3865a6010100049f803aaf544262eb522c5ce2332f018cac4d9817b6fddda97d12b01bcdaf56f92bf1ea0b3d0d969cb5d3c1d5fce9eba043d340b76ba7f44e4fc83d6f753517cf0220210ac040800100c040810100240153f89ded5a391aed0303181db9cf7c052616001db9566e0526872a1d53f0d0052783500000d8dfca3197ff2177e8d7e169266a7e78192f0c656ceb07f1e2035044509c05609c7efb2f953a2019d7a0c7a0cd7ce5a52cc1544ee92cafa74857b1489f419f46"
		Certificate cert = deserializeFromHex(new Certificate(),atCertOrgString);
		return cert;
	}
	
	private SecuredMessage genSecuredMessage(SignerInfoType signerInfoType, Certificate senderCertificate, byte[] payLoad){
		if(signerInfoType != SignerInfoType.certificate && signerInfoType != SignerInfoType.certificate_digest_with_ecdsap256){
			throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);
		}
		
		List<HeaderField> headerFields = new ArrayList<HeaderField>();
		headerFields.add(new HeaderField(new Time64(new Date()))); // generate generation time
		headerFields.add(new HeaderField(MessageType.CAM.getValue())); // generate generation time
		if(signerInfoType == SignerInfoType.certificate){
			headerFields.add(new HeaderField(new SignerInfo(senderCertificate)));
		}else{
			try {
				HashedId8 hash = new HashedId8(defaultCryptoManager.digest(senderCertificate.getEncoded(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256));
				headerFields.add(new HeaderField(new SignerInfo(hash)));
			} catch (NoSuchAlgorithmException e) {
				throw new SignatureException("Error generating secured message, no such algorithm: " + e.getMessage(),e);
			}
		}
		
		List<Payload> pl = new ArrayList<Payload>();
		if(payLoad == null){
			pl.add(new Payload(PayloadType.signed,new byte[0]));
		}else{
			pl.add(new Payload(PayloadType.signed,payLoad));
		}
		
		return new SecuredMessage(MessageType.CAM.securityProfile, headerFields, pl);
	}
	
	
}

