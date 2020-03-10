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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId10;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.HashBasedRevocationInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfHashBasedRevocationInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedHashIdCrl;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ToBeSignedHashIdCrl
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class ToBeSignedHashIdCrlSpec extends BaseStructSpec {

	HashedId10 h1 = new HashedId10(Hex.decode("01020304050607080910"))
	HashedId10 h2 = new HashedId10(Hex.decode("11121314051617181920"))
	
	Time32 t1 = new Time32(7000)
	Time32 t2 = new Time32(9000)
	
	HashBasedRevocationInfo hr1 = new HashBasedRevocationInfo(h1,t1)
	HashBasedRevocationInfo hr2 = new HashBasedRevocationInfo(h2,t2)
	
	SequenceOfHashBasedRevocationInfo entries = new SequenceOfHashBasedRevocationInfo([hr1,hr2])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		ToBeSignedHashIdCrl tbs1 = new ToBeSignedHashIdCrl(4,entries)
		then:
		tbs1.hasExtension
		serializeToHex(tbs1) == "000000000401020102030405060708091000001b581112131405161718192000002328"
		when:
		ToBeSignedHashIdCrl tbs2 = deserializeFromHex(new ToBeSignedHashIdCrl(), "000000000401020102030405060708091000001b581112131405161718192000002328")
		then:
		tbs2.hasExtension
		tbs2.getCrlSerial() == 4
		tbs2.getEntries() == entries
	}
	
	def "Verify that IOException is thrown if not all fields are set"(){
		when:
		new ToBeSignedHashIdCrl(5,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new ToBeSignedHashIdCrl(4,entries).toString() == """ToBeSignedHashIdCrl [
  crlSerial=4,
  entries=[
    [id=[01020304050607080910], expiry=[timeStamp=Thu Jan 01 02:56:40 CET 2004 (7000)]],
    [id=[11121314051617181920], expiry=[timeStamp=Thu Jan 01 03:30:00 CET 2004 (9000)]]
  ]
]"""
	}
	

}
