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


import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.UncompressedEccPoint
import spock.lang.Shared
import spock.lang.Unroll

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPublicKeySpec

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.*
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256

/**
 * Unit tests for DefaultCryptoManager
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DefaultCryptoManagerSpec extends BaseStructSpec {
	
	@Shared DefaultCryptoManager defaultCryptoManager = new DefaultCryptoManager()
	@Shared KeyPairGenerator sunKeyGenerator = KeyPairGenerator.getInstance("EC", "SunEC")
	
	@Shared KeyPair p256SigKeys
	@Shared KeyPair p256EncKeys

	@Shared KeyPair brainPool256SignKeys
	@Shared KeyPair brainPool256EncKeys

	@Shared KeyPair brainPool384SignKeys
	@Shared KeyPair brainPool384EncKeys

	def setupSpec(){
		def subParamSpec
		try{
			subParamSpec = sun.security.ec.NamedCurve.getECParameterSpec("secp256r1")
		}catch(MissingMethodException e){
		    subParamSpec  = sun.security.util.ECUtil.getECParameterSpec(null, "secp256r1") 
		}
		sunKeyGenerator.initialize(subParamSpec, new SecureRandom())
		
		defaultCryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		p256SigKeys = defaultCryptoManager.generateKeyPair(ecdsaNistP256)
		p256EncKeys = defaultCryptoManager.generateKeyPair(ecdsaNistP256)
		brainPool256SignKeys = defaultCryptoManager.generateKeyPair(ecdsaBrainpoolP256r1)
		brainPool256EncKeys = defaultCryptoManager.generateKeyPair(ecdsaBrainpoolP256r1)
		brainPool384SignKeys = defaultCryptoManager.generateKeyPair(ecdsaBrainpoolP256r1)
		brainPool384EncKeys = defaultCryptoManager.generateKeyPair(ecdsaBrainpoolP256r1)
	}

	@Unroll
	def "verify that generateKeyPair generates new key pairs for algorithm: #pubAlg"(){
		when:
		KeyPair k1 = defaultCryptoManager.generateKeyPair(pubAlg)
		KeyPair k2 = defaultCryptoManager.generateKeyPair(pubAlg)
		then:
		k1 != k2
		k1 != null
		where:
		pubAlg << [ BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1,
			ecdsaNistP256, ecdsaBrainpoolP256r1, ecdsaBrainpoolP384r1]
	}
	@Unroll
	def "Verify that ieee encodeEccPoint encodes P256 ec public keys properly for algorithm: #pubAlg"(){
		setup:
		ECPublicKey pubKey1 = defaultCryptoManager.generateKeyPair(pubAlg).getPublic()
		BigInteger pubKey1_x = pubKey1.getW().getAffineX()
		BigInteger pubKey1_y = pubKey1.getW().getAffineY()
		when:
		EccP256CurvePoint p1 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.xonly, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p1.getChoice() == EccP256CurvePointChoices.xonly
		((COEROctetStream) p1.getValue()).getData() == EccP256CurvePoint.fromBigInteger(pubKey1_x)
		when:
		EccP256CurvePoint p2 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.compressedy0, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p2.getChoice() == EccP256CurvePointChoices.compressedy1 || p2.getChoice() == EccP256CurvePointChoices.compressedy0
		((COEROctetStream) p2.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineY() == pubKey1_y
		
		
		when:
		EccP256CurvePoint p3 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.compressedy1, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p3.getChoice() == EccP256CurvePointChoices.compressedy1 || p3.getChoice() == EccP256CurvePointChoices.compressedy0
		((COEROctetStream) p3.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineY() == pubKey1_y
		
		when:
		EccP256CurvePoint p4 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP256CurvePointChoices.uncompressed, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		UncompressedEccPoint uec = p4.value
		then:
		p4.getChoice() == EccP256CurvePointChoices.uncompressed
		new BigInteger(1,uec.getX()) == pubKey1_x
		new BigInteger(1,uec.getY()) == pubKey1_y
		
		where:
		pubAlg << [ecdsaNistP256, ecdsaBrainpoolP256r1]
	}

	@Unroll
	def "Verify that ieee encodeEccPoint encodes P384 ec public keys properly for algorithm: #pubAlg"(){
		setup:
		ECPublicKey pubKey1 = defaultCryptoManager.generateKeyPair(pubAlg).getPublic()
		BigInteger pubKey1_x = pubKey1.getW().getAffineX()
		BigInteger pubKey1_y = pubKey1.getW().getAffineY()
		when:
		EccP384CurvePoint p1 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP384CurvePoint.EccP384CurvePointChoices.xonly, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p1.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.xonly
		((COEROctetStream) p1.getValue()).getData() == EccP384CurvePoint.fromBigInteger(pubKey1_x)
		when:
		EccP384CurvePoint p2 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP384CurvePoint.EccP384CurvePointChoices.compressedy0, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p2.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.compressedy1 || p2.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.compressedy0
		((COEROctetStream) p2.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p2)).getW().getAffineY() == pubKey1_y


		when:
		EccP384CurvePoint p3 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP384CurvePoint.EccP384CurvePointChoices.compressedy1, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		then:
		p3.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.compressedy1 || p3.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.compressedy0
		((COEROctetStream) p3.getValue()).getData() != null
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineX() == pubKey1_x
		((ECPublicKey) defaultCryptoManager.decodeEccPoint(pubAlg, p3)).getW().getAffineY() == pubKey1_y

		when:
		EccP384CurvePoint p4 = defaultCryptoManager.encodeEccPoint(pubAlg, EccP384CurvePoint.EccP384CurvePointChoices.uncompressed, constructKey(pubAlg,pubKey1_x, pubKey1_y))
		UncompressedEccPoint uec = p4.value
		then:
		p4.getChoice() == EccP384CurvePoint.EccP384CurvePointChoices.uncompressed
		new BigInteger(1,uec.getX()) == pubKey1_x
		new BigInteger(1,uec.getY()) == pubKey1_y

		where:
		pubAlg << [ecdsaBrainpoolP384r1]
	}
	
	@Unroll
	def "Verify that decodeEccPoint decodes the ieee P256 EccPoints correctly for public key scheme: #pubAlg"(){
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
		pubAlg << [ecdsaNistP256, ecdsaBrainpoolP256r1]
	}

	@Unroll
	def "Verify that decodeEccPoint decodes the ieee P384 EccPoints correctly for public key scheme: #pubAlg"(){
		setup:
		BCECPublicKey pubKey1 = defaultCryptoManager.generateKeyPair(pubAlg).getPublic()
		BigInteger pubKey1_x = pubKey1.getW().getAffineX()
		BigInteger pubKey1_y = pubKey1.getW().getAffineY()
		when: // verify x_coordinate_only
		EccP384CurvePoint x_onlyPoint = new EccP384CurvePoint(pubKey1_x)
		Object result = defaultCryptoManager.decodeEccPoint(pubAlg, x_onlyPoint)
		then:
		result instanceof BigInteger
		result == pubKey1_x

		when: // verify compressed_y
		EccP384CurvePoint compressed_point = new EccP384CurvePoint(pubKey1.getQ().getEncoded(true))
		result = defaultCryptoManager.decodeEccPoint(pubAlg, compressed_point)

		then:
		result instanceof ECPublicKey
		result != null

		when: // verify uncompressed_point
		EccP384CurvePoint uncompressed_point = new EccP384CurvePoint(pubKey1.getW().getAffineX(),pubKey1.getW().getAffineY())
		result = defaultCryptoManager.decodeEccPoint(pubAlg, uncompressed_point)

		then:
		result instanceof ECPublicKey
		result != null

		where:
		pubAlg << [ecdsaBrainpoolP384r1]
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

	
	def "Verify that getECCurve returns correct curve"(){
		expect:
		defaultCryptoManager.getECCurve(ecdsaNistP256).q == new BigInteger(1,Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"))
		defaultCryptoManager.getECCurve(eciesNistP256).q == new BigInteger(1,Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"))
		// TODO
	}
	
	@Unroll
	def "Verify that getECCurve getECParameterSpec returns curve with name: #name for public key algorithm: #pubAlg"(){
		expect:
		defaultCryptoManager.getECParameterSpec(pubAlg).name == name
		where:
		pubAlg                                          | name
		ecdsaNistP256                                   | "P-256"
		eciesNistP256                                   | "P-256"
		// TODO
	}
	
	def "Verify that convertECPublicKeyToBCECPublicKey supports both BC and SUN Public keys"(){
		expect:
		defaultCryptoManager.toBCECPublicKey(eciesNistP256,
			defaultCryptoManager.generateKeyPair(eciesNistP256).publicKey) instanceof BCECPublicKey
		defaultCryptoManager.toBCECPublicKey(eciesNistP256,
			sunKeyGenerator.generateKeyPair().publicKey) instanceof BCECPublicKey
		
	}
	

	// TODO verifySelfSigned, reference to test
	
//	def "Verify that eCEISEncryptSymmetricKey and eCEISDecryptSymmetricKey encrypts and decrypts symmetric key correcly."(){
//		setup:
//		KeyGenerator kgen = KeyGenerator.getInstance("AES","BC")
//		kgen.init(128)
//		SecretKey key = kgen.generateKey()
//		KeyPair kp = defaultCryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
//		when:
//		def ecies = defaultCryptoManager.itsEceisEncryptSymmetricKeyVer2(PublicKeyAlgorithm.ecies_nistp256, kp.getPublic(), key)
//		then:
//		ecies.v != null
//		ecies.c != null
//		ecies.t != null
//		when:
//		SecretKey decryptedKey = defaultCryptoManager.itsEciesDecryptSymmetricKeyVer2(ecies, kp.getPrivate())
//		then:
//		key.getEncoded() == decryptedKey.getEncoded()
//	}




	def "Verify that symmetric encrypt and decrypt works for aes_128_ccm"(){
		setup:
		KeyGenerator kgen = KeyGenerator.getInstance("AES","BC")
		kgen.init(128)
		SecretKey key = kgen.generateKey()
		SecureRandom random = new SecureRandom()
		byte[] nounce = new byte[12]
		random.nextBytes(nounce)
		int dataSize = random.nextInt(10000)
		
		byte[] data = new byte[dataSize]
		random.nextBytes(data)
		
		when:
		byte[] encryptedData = defaultCryptoManager.symmetricEncryptIEEE1609_2_2017(SymmAlgorithm.aes128Ccm, data, key.encoded, nounce)
		byte[] decryptedData = defaultCryptoManager.symmetricDecryptIEEE1609_2_2017(SymmAlgorithm.aes128Ccm, encryptedData, key.encoded, nounce)
		then:
		encryptedData != data
		decryptedData == data
	}

	def "Verify that getSignatureChoice returns #sigChoice for alg #sigAlg"(){
		expect:
		defaultCryptoManager.getSignatureChoice(sigAlg) == sigChoice
		where:
		sigChoice                                      | sigAlg
		SignatureChoices.ecdsaNistP256Signature        | Algorithm.Signature.ecdsaNistP256
		SignatureChoices.ecdsaBrainpoolP256r1Signature | Algorithm.Signature.ecdsaBrainpoolP256r1
		SignatureChoices.ecdsaBrainpoolP384r1Signature | Algorithm.Signature.ecdsaBrainpoolP384r1
	}

	private ECPublicKey constructKey(AlgorithmIndicator alg, BigInteger x, BigInteger y){
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
		String curveName = alg.algorithm.signature.getCurveName() == "P-256" ? "secp256r1" : alg.algorithm.signature.getCurveName()
        parameters.init(new ECGenParameterSpec(curveName))
        java.security.spec.ECParameterSpec ecParameters = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
        return KeyFactory.getInstance("EC", "BC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), ecParameters))
	}

}

