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
package org.certificateservices.custom.c2x.ieee1609dot2.crl.basic

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId10
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageSeed;
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

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SequenceOfHashBasedRevocationInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfHashBasedRevocationInfoSpec extends BaseStructSpec {

	HashedId10 h1 = new HashedId10(Hex.decode("01020304050607080910"))
	HashedId10 h2 = new HashedId10(Hex.decode("11121314051617181920"))
	
	Time32 t1 = new Time32(7000)
	Time32 t2 = new Time32(9000)
	
	HashBasedRevocationInfo hr1 = new HashBasedRevocationInfo(h1,t1)
	HashBasedRevocationInfo hr2 = new HashBasedRevocationInfo(h2,t2)
	
	def "Verify that SequenceOfHashBasedRevocationInfo is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfHashBasedRevocationInfo(),"01020102030405060708091000001b581112131405161718192000002328")
		then:
		u1.getSequenceValues()[0] == hr1
		u1.getSequenceValues()[1] == hr2
		when:
		def u2 = new SequenceOfHashBasedRevocationInfo([hr1,hr2] as HashBasedRevocationInfo[])
		then:
		u2.getSequenceValues()[0] == hr1
		u2.getSequenceValues()[1] == hr2
		
		when:
		def u3 = new SequenceOfHashBasedRevocationInfo([hr1,hr2])
		then:
		u3.getSequenceValues()[0] == hr1
		u3.getSequenceValues()[1] == hr2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfHashBasedRevocationInfo([hr1,hr2]).toString() == """SequenceOfHashBasedRevocationInfo [
  [id=[01020304050607080910], expiry=[timeStamp=Thu Jan 01 02:56:40 CET 2004 (7000)]],
  [id=[11121314051617181920], expiry=[timeStamp=Thu Jan 01 03:30:00 CET 2004 (9000)]]
]"""
		new SequenceOfHashBasedRevocationInfo().toString() == "SequenceOfHashBasedRevocationInfo []"
		new SequenceOfHashBasedRevocationInfo([hr1]).toString() == """SequenceOfHashBasedRevocationInfo [
  [id=[01020304050607080910], expiry=[timeStamp=Thu Jan 01 02:56:40 CET 2004 (7000)]]
]"""
		
	
	}
	

	
	


}
