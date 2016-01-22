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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Ieee1609dot2Peer2PeerPDU
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class Ieee1609dot2Peer2PeerPDUSpec extends BaseStructSpec {

	Certificate cert1 = CaCertP2pPDUSpec.genCertificate("cert1")
	Certificate cert2 = CaCertP2pPDUSpec.genCertificate("cert2")
	
	Ieee1609dot2Peer2PeerPDUContent caCert = new Ieee1609dot2Peer2PeerPDUContent(new CaCertP2pPDU([cert1,cert2]))
	Ieee1609dot2Peer2PeerPDUContent crl = new Ieee1609dot2Peer2PeerPDUContent()
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		Ieee1609dot2Peer2PeerPDU d1 = new Ieee1609dot2Peer2PeerPDU(4,crl)
		then:
		serializeToHex(d1) == "0481"
		when:
		Ieee1609dot2Peer2PeerPDU d2 = deserializeFromHex(new Ieee1609dot2Peer2PeerPDU(), "0481")
		then:
		d2.getVersion() == 04
		d2.getContent() == crl
		
		when:
		Ieee1609dot2Peer2PeerPDU d3 = new Ieee1609dot2Peer2PeerPDU(crl)
		then:
		serializeToHex(d3) == "0181"
		when:
		Ieee1609dot2Peer2PeerPDU d4 = deserializeFromHex(new Ieee1609dot2Peer2PeerPDU(), "0181")
		then:
		d4.getVersion() == 01
		d4.getContent() == crl
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new Ieee1609dot2Peer2PeerPDU(null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new Ieee1609dot2Peer2PeerPDU(crl).toString() == """Ieee1609dot2Peer2PeerPDU [
  version=1,
  content=[crl]
]"""
		new Ieee1609dot2Peer2PeerPDU(caCert).toString() == """Ieee1609dot2Peer2PeerPDU [
  version=1,
  content=[caCerts=[
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
  ]]]
]"""
	}
	

}
