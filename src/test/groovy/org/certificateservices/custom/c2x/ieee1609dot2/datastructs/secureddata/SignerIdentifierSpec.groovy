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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificateSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SignerIdentifier
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SignerIdentifierSpec extends BaseStructSpec {
	
	@Shared HashedId8 h = new HashedId8(Hex.decode("0102030405060708"))
	
	@Shared SequenceOfCertificate c = new SequenceOfCertificate(SequenceOfCertificateSpec.genCertificate("test1"), SequenceOfCertificateSpec.genCertificate("test2"))
		
	@Unroll
	def "Verify that SignerIdentifier is correctly encoded for type #choice"(){
		when:
		def si = value
		
		then:
		serializeToHex(si) == encoding
		
		when:
		SignerIdentifier si2 = deserializeFromHex(new SignerIdentifier(), encoding)
		
		then:
		si2.getValue() == value.getValue()
		si2.choice == choice
		si2.type == choice
		!choice.extension
		
		where:
		choice                                              | value                    | encoding   
		SignerIdentifierChoices.digest                      | new SignerIdentifier(h)  | "800102030405060708"   
		SignerIdentifierChoices.certificate                 | new SignerIdentifier(c)  | "8101028003008100108105746573743131323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5808084000000000000000000000000000000000000000000000000000000000000015900000000000000000000000000000000000000000000000000000000000001bd8080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58003008100108105746573743231323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5808084000000000000000000000000000000000000000000000000000000000000015900000000000000000000000000000000000000000000000000000000000001bd8080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		SignerIdentifierChoices.self                        | new SignerIdentifier()   | "82"
	}

	
	def "Verify toString"(){
		expect:
		new SignerIdentifier(h).toString() == "SignerIdentifier [digest=0102030405060708]"
		new SignerIdentifier(c).toString() == """SignerIdentifier [certificate=[
Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[test1]]
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
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000159, y=00000000000000000000000000000000000000000000000000000000000001bd]]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
],
Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[test2]]
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
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000159, y=00000000000000000000000000000000000000000000000000000000000001bd]]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
]]]"""
		new SignerIdentifier().toString() == "SignerIdentifier [self]"
	}
	

}
