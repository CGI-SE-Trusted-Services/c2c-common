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
package org.certificateservices.custom.c2x.ieee1609dot2.cert

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Certificate
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CertificateSpec extends BaseStructSpec {

	ToBeSignedCertificate implicitToBeSigned = genToBeSignedCertificate(true)
	ToBeSignedCertificate explicitToBeSigned = genToBeSignedCertificate(false)
	IssuerIdentifier issuerId = new IssuerIdentifier(HashAlgorithm.sha256)
	Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(new EccP256CurvePoint(new BigInteger(123)),COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)))


	def "Verify that constructor and getters are correct and it is correctly encoded for explicit certificates"(){
		when:
		
		Certificate c = new Certificate(issuerId, explicitToBeSigned, signature);
		then:
		serializeToHex(c) == "80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		Certificate c2 = deserializeFromHex(new Certificate(), "80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		c2.getVersion() == Certificate.CURRENT_VERSION
		c2.getType() == CertificateType.explicit
		c2.getIssuer() == issuerId
		c2.getToBeSigned() == explicitToBeSigned
		c2.getSignature() == signature
		

		when:
		
		Certificate c3 = new Certificate(4,issuerId, explicitToBeSigned, signature);
		then:
		serializeToHex(c3) == "80040081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		Certificate c4 = deserializeFromHex(new Certificate(), "80040081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		c4.getVersion() == 4
	}
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded for implicit certificates"(){
		when:
		
		Certificate c = new Certificate(issuerId, implicitToBeSigned);
		then:
		serializeToHex(c) == "00030181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7"
		when:
		Certificate c2 = deserializeFromHex(new Certificate(), "00030181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7")
		then:
		c2.getVersion() == Certificate.CURRENT_VERSION
		c2.getType() == CertificateType.implicit
		c2.getIssuer() == issuerId
		c2.getToBeSigned() == implicitToBeSigned
		c2.getSignature() == null
		

		when:
		Certificate c3 = new Certificate(4,issuerId, implicitToBeSigned);
		then:
		
		serializeToHex(c3) == "00040181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7"
		when:
		Certificate c4 = deserializeFromHex(new Certificate(), "00040181007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7")
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
    certIssuePermissions=[[appPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
    certRequestPermissions=[[appPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
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
    certIssuePermissions=[[appPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
    certRequestPermissions=[[appPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
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
	
	
	private ToBeSignedCertificate genToBeSignedCertificate(boolean implicit){
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


def referenceDataStruct ="""
0381004003800F546869732069732061 
2042534D0D0A40012011121314151617
18810101000301802122232425262728
50808000643132333435363738394142
43445152535455565758596162630046
04E09A208400A983010380007C8001E4
80034801020001200001268182919293
94959697989192939495969798919293
94959697989192939495969798808231
32333435363738313233343536373831
32333435363738313233343536373841
42434445464748414243444546474841
424344454647484142434445464748"""	
	
}
