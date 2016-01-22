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
package org.certificateservices.custom.c2x.ieee1609dot2.p2p

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext.SymmetricCiphertextChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.p2p.Ieee1609dot2Peer2PeerPDUContent.Ieee1609dot2Peer2PeerPDUContentChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Ieee1609dot2Peer2PeerPDUContent
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Ieee1609dot2Peer2PeerPDUContentSpec extends BaseStructSpec {
	
	@Shared Certificate cert1 = CaCertP2pPDUSpec.genCertificate("cert1")
	@Shared Certificate cert2 = CaCertP2pPDUSpec.genCertificate("cert2")
	
	@Shared Ieee1609dot2Peer2PeerPDUContent caCert = new Ieee1609dot2Peer2PeerPDUContent(new CaCertP2pPDU([cert1,cert2]))
	@Shared Ieee1609dot2Peer2PeerPDUContent crl = new Ieee1609dot2Peer2PeerPDUContent()
	
	@Unroll
	def "Verify that Ieee1609dot2Peer2PeerPDUContent is correctly encoded for type #choice"(){
		when:
		def o = value
		
		then:
		serializeToHex(o) == encoding
		
		when:
		Ieee1609dot2Peer2PeerPDUContent o2 = deserializeFromHex(new Ieee1609dot2Peer2PeerPDUContent(), encoding)
		
		then:
		o2.getValue() == value.getValue()
		o2.choice == choice
		o2.type == choice
		
		where:
		choice                                              | value                            | encoding   
		Ieee1609dot2Peer2PeerPDUContentChoices.caCerts      | caCert                           | "8001028003008100108105636572743131323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580808300000000000000000000000000000000000000000000000000000000000001598080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58003008100108105636572743231323301b016a58f248400050102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580808300000000000000000000000000000000000000000000000000000000000001598080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		Ieee1609dot2Peer2PeerPDUContentChoices.crl          | crl                              | "81"
		
	}

	
	def "Verify toString()"(){
		expect:
		caCert.toString() == """Ieee1609dot2Peer2PeerPDUContent [caCerts=[
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
]]]"""
		crl.toString() == "Ieee1609dot2Peer2PeerPDUContent [crl]"
		
		
	}
	

}
