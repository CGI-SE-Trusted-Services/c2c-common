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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfCertificate class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfCertificateSpec extends BaseStructSpec {

	Certificate cert1 = genCertificate("cert1")
	Certificate cert2 = genCertificate("cert2")
	
	def "Verify that SequenceOfCertificate is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfCertificate(),"01028003008100108105636572743131323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580808300000000000000000000000000000000000000000000000000000000000001598080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58003008100108105636572743231323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580808300000000000000000000000000000000000000000000000000000000000001598080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		u1.getSequenceValues()[0] == cert1
		u1.getSequenceValues()[1] == cert2
		when:
		def u2 = new SequenceOfCertificate([cert1,cert2] as Certificate[])
		then:
		u2.getSequenceValues()[0] == cert1
		u2.getSequenceValues()[1] == cert2
		
		when:
		def u3 = new SequenceOfCertificate([cert1,cert2])
		then:
		u3.getSequenceValues()[0] == cert1
		u3.getSequenceValues()[1] == cert2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfCertificate([cert1,cert2]).toString() == """SequenceOfCertificate [
Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[cert1]]
    cracaId=[313233]
    crlSeries=[432]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=NONE
    assuranceLevel=NONE
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=0000000000000000000000000000000000000000000000000000000000000159]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
],
Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[cert2]]
    cracaId=[313233]
    crlSeries=[432]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=NONE
    assuranceLevel=NONE
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=0000000000000000000000000000000000000000000000000000000000000159]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
]]"""
		new SequenceOfCertificate().toString() == "SequenceOfCertificate []"
		new SequenceOfCertificate([cert1]).toString() == """SequenceOfCertificate [
Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[cert1]]
    cracaId=[313233]
    crlSeries=[432]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=NONE
    assuranceLevel=NONE
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=0000000000000000000000000000000000000000000000000000000000000159]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
]]"""
		
	
	}
	
	private static Certificate genCertificate(String idString){
		byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
		ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, sspData)

		byte[] x2 = new BigInteger(345).toByteArray()
		EccP256CurvePoint p2 = new EccP256CurvePoint(EccP256CurvePointChoices.compressedy1,x2)
		PublicVerificationKey pvk = new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, p2)

		CertificateId id = new CertificateId(new Hostname(idString))
		HashedId3 cracaId = new HashedId3("123".bytes)
		CrlSeries crlSeries  = new CrlSeries(432)
		ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(DurationChoices.hours, 5))
		SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp),new PsidSsp(new Psid(202), ssp)])

		VerificationKeyIndicator verifyKeyIndicator_vk = new VerificationKeyIndicator(pvk)
		
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, cracaId, crlSeries, validityPeriod, null, null, appPermissions, null, null, false, null, verifyKeyIndicator_vk)
		
		IssuerIdentifier issuerId = new IssuerIdentifier(HashAlgorithm.sha256)
		Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(new EccP256CurvePoint(EccP256CurvePointChoices.xonly,new BigInteger(123).toByteArray()),COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)))
	
		return new Certificate(issuerId,tbs,signature)
	}
	
	


}
