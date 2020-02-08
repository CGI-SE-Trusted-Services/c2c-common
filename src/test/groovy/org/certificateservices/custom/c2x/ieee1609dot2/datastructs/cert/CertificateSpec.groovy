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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8

import java.security.KeyPair
import java.security.PublicKey;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.Certificate.Type;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Certificate
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CertificateSpec extends  BaseCertGeneratorSpec {

	ToBeSignedCertificate implicitToBeSigned = genToBeSignedCertificate(true)
	ToBeSignedCertificate explicitToBeSigned = genToBeSignedCertificate(false)
	IssuerIdentifier issuerId = new IssuerIdentifier(HashAlgorithm.sha256)
	Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(new EccP256CurvePoint(new BigInteger(123)),COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)))


	def "Verify that constructor and getters are correct and it is correctly encoded for explicit certificates"(){
		when:
		
		Certificate c = new Certificate(issuerId, explicitToBeSigned, signature)
		then:
		serializeToHex(c) == "80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		Certificate c2 = deserializeFromHex(new Certificate(), "80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		c2.getVersion() == Certificate.CURRENT_VERSION
		c2.getType() == CertificateType.explicit
		c2.getIssuer() == issuerId
		c2.getToBeSigned() == explicitToBeSigned
		c2.getSignature() == signature
		

		when:
		
		Certificate c3 = new Certificate(4,issuerId, explicitToBeSigned, signature);
		then:
		serializeToHex(c3) == "80040081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		Certificate c4 = deserializeFromHex(new Certificate(), "80040081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		c4.getVersion() == 4
	}
	
	@Unroll
	def "Verify that getType and getPublicKey works for both implicit and explicit certificates for alg #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		Certificate explicitCert = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		Certificate implicitCert = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey implicitPubKey = ecqvHelper.extractPublicKey(implicitCert, rootCAKeys.getPublic(), alg, rootCA)
		
		expect:
		implicitCert.getCertificateType() == Type.IMPLICIT
		explicitCert.getCertificateType() == Type.EXPLICIT
		
		explicitCert.getPublicKey(cryptoManager, null, null, null).encoded == enrollCAKeys.getPublic().encoded
		implicitCert.getPublicKey(cryptoManager, alg, rootCA, rootCAKeys.getPublic()).encoded == implicitPubKey.encoded
		where:
		alg << [SignatureChoices.ecdsaNistP256Signature, SignatureChoices.ecdsaBrainpoolP256r1Signature]
	}
	
	def "Verify that getPublicKey throws IllegalArgumentException if invalid parameters was given"(){
		setup:
		def alg = SignatureChoices.ecdsaNistP256Signature
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		Certificate explicitCert = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		Certificate implicitCert = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey implicitPubKey = ecqvHelper.extractPublicKey(implicitCert, rootCAKeys.getPublic(), alg, rootCA)
		when:
		explicitCert.getPublicKey(null, null, null, null)
		then:
		thrown IllegalArgumentException
		when:
		implicitCert.getPublicKey(null, null, null, null)
		then:
		thrown IllegalArgumentException
		when:
		implicitCert.getPublicKey(cryptoManager, null, null, null)
		then:
		thrown IllegalArgumentException
		when:
		implicitCert.getPublicKey(cryptoManager, alg, null, null)
		then:
		thrown IllegalArgumentException
		when:
		implicitCert.getPublicKey(cryptoManager, alg, rootCA, null)
		then:
		thrown IllegalArgumentException
		
	}
	
	def "Verify that constructor and getters are correct and it is correctly encoded for implicit certificates"(){
		when:
		
		Certificate c = new Certificate(issuerId, implicitToBeSigned);
		then:
		serializeToHex(c) == "00030181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7"
		when:
		Certificate c2 = deserializeFromHex(new Certificate(), "00030181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7")
		then:
		c2.getVersion() == Certificate.CURRENT_VERSION
		c2.getType() == CertificateType.implicit
		c2.getIssuer() == issuerId
		c2.getToBeSigned() == implicitToBeSigned
		c2.getSignature() == null
		

		when:
		Certificate c3 = new Certificate(4,issuerId, implicitToBeSigned);
		then:
		
		serializeToHex(c3) == "00040181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7"
		when:
		Certificate c4 = deserializeFromHex(new Certificate(), "00040181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7")
		then:
		c4.getVersion() == 4
	}
	
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
	
		when:
		new Certificate(null,explicitToBeSigned, signature)
		then:
		thrown IllegalArgumentException
		when:
		new Certificate(issuerId,null, signature)
		then:
		thrown IllegalArgumentException
		when:
		new Certificate(null,implicitToBeSigned)
		then:
		thrown IllegalArgumentException
		when:
		new Certificate(issuerId,null)
		then:
		thrown IllegalArgumentException
	} 
	
	def "Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for explicit certificate"(){
	   when:
	   new Certificate(issuerId, implicitToBeSigned, signature);
	   then:
	   thrown IllegalArgumentException	
	   when:
	   new Certificate(issuerId, implicitToBeSigned, null);
	   then:
	   thrown IllegalArgumentException
    }
	
	def "Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists for implicit certificate"(){
		when:
		new Certificate(issuerId, explicitToBeSigned);
		then:
		thrown IllegalArgumentException
	 }

	String referenceCert = normalizeHex"""00030180 01010101 01010101 50800000 02030303 03030303 03030404 04000506
06060684 00A98301 0380007C 8001E480 03480101 00012081 83080808 08080808
08080808 08080808 08080808 08080808 08080808 08080808 08"""


	def "Check reference certificate"(){
		when:
		Certificate c = new Certificate(Hex.decode(referenceCert))
		then:
		serializeToHex(c) == referenceCert
	}

	def "Verify that asHashedId8 generates SHA-256 digest HashedId8 of certificate"(){
		setup:
		Certificate c = new Certificate(Hex.decode(referenceCert))
		when:
		HashedId8 id = c.asHashedId8(cryptoManager)
		then:
		new HashedId8(cryptoManager.digest(c.encoded,HashAlgorithm.sha256)) == id
	}

	String coerExternalReferenceCert = normalizeHex """80 03 00 80 00 00 00 00 00 00 00 00 04 83 00 00
00 00 00 00 00 00 00 80 00 00 01 01 00 80 01 01
00 01 00 80 80 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 80 80 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00"""


	def "Verify that external reference certificate is decoded and encoded back to same values"(){
		when:
		Certificate c = new Certificate(Hex.decode(coerExternalReferenceCert))
		then:
		serializeToHex(c) == coerExternalReferenceCert
	}

	byte[] referenceImplicitCert =Hex.decode("000301802122232425262728508080006431323334353637383941424344515253545556575859616263004604E09A208400A983010380007C8001E4800348010200012000012681829192939495969798919293949596979891929394959697989192939495969798")
	
	def "Verify that it is possible to parse the reference implicit certificate"(){
		when:
		Certificate c = new Certificate(referenceImplicitCert)
		then:
		c.toString() == """Certificate [
  version=3
  type=implicit
  issuer=[sha256AndDigest=[2122232425262728]]
  toBeSigned=[
    id=[linkageData=[iCert=[100], linkage-value=[313233343536373839], group-linkage-value=[jvalue=41424344, value=515253545556575859]]]
    cracaId=[616263]
    crlSeries=[70]
    validityPeriod=[start=Time32 [timeStamp=Sat Aug 05 04:06:23 CEST 2006 (81828384)], duration=Duration [169 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [124]],[CountryOnly [484]],[CountryOnly [840]]]]
    assuranceLevel=NONE
    appPermissions=[[psid=[32(20)], ssp=NULL],[psid=[38(26)], ssp=NULL]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[reconstructionValue=[compressedy0=9192939495969798919293949596979891929394959697989192939495969798]]
  ]
  signature=NONE
]"""
	
	c.encoded == referenceImplicitCert
		
	}

	
	String explicitString =
"""Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[SomeCertId]]
    cracaId=[313233]
    crlSeries=[432]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
    assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
    certRequestPermissions=[[subjectPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
    canRequestRollover=true
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
]"""

  String implicitString =
"""Certificate [
  version=3
  type=implicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[SomeCertId]]
    cracaId=[313233]
    crlSeries=[432]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
    assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
    certRequestPermissions=[[subjectPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
    canRequestRollover=true
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
    verifyKeyIndicator=[reconstructionValue=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]
  ]
  signature=NONE
]"""

	def "Verify toString"(){
		expect:
		 new Certificate(issuerId, explicitToBeSigned, signature).toString() == explicitString
		 new Certificate(issuerId, implicitToBeSigned).toString() == implicitString
	}
	
	
	static ToBeSignedCertificate genToBeSignedCertificate(boolean implicit){
		byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
		ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, sspData)
		
		
		EccP256CurvePoint p1 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
		BasePublicEncryptionKey pubKey1 = new BasePublicEncryptionKey(BasePublicEncryptionKeyChoices.ecdsaNistP256, p1)
		
		EccP256CurvePoint p2 = new EccP256CurvePoint(new BigInteger(323),new BigInteger(423))
		PublicVerificationKey pvk = new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, p2)
		
		PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
		PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))
		
		PsidGroupPermissions perm3 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),5,6,new EndEntityType(true, true))
		PsidGroupPermissions perm4 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),7,8,new EndEntityType(false, true))
		
		CertificateId id = new CertificateId(new Hostname("SomeCertId"))
		HashedId3 cracaId = new HashedId3("123".bytes)
		CrlSeries crlSeries  = new CrlSeries(432)
		ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(DurationChoices.hours, 5))
		GeographicRegion region = new GeographicRegion(GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(9))))
		SubjectAssurance assuranceLevel = new SubjectAssurance(3,2)
		SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp),new PsidSsp(new Psid(202), ssp)])
		SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions([perm1,perm2])
		SequenceOfPsidGroupPermissions certRequestPermissions = new SequenceOfPsidGroupPermissions([perm3,perm4])
		boolean canRequestRollover = true
		PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey1)
		VerificationKeyIndicator verifyKeyIndicator_rv = new VerificationKeyIndicator(p2)
		VerificationKeyIndicator verifyKeyIndicator_vk = new VerificationKeyIndicator(pvk)
		
		return new ToBeSignedCertificate(id, cracaId, crlSeries, validityPeriod, region, assuranceLevel, appPermissions, certIssuePermissions, certRequestPermissions, canRequestRollover, encryptionKey, (implicit? verifyKeyIndicator_rv : verifyKeyIndicator_vk))
	}
	
}
