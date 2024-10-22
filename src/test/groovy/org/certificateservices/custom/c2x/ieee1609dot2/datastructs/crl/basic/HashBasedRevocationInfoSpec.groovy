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
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for HashBasedRevocationInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class HashBasedRevocationInfoSpec extends BaseStructSpec {

	
	HashedId10 h1 = new HashedId10(Hex.decode("01020304050607080910"))
	
	Time32 t1 = new Time32(7000)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		HashBasedRevocationInfo hr1 = new HashBasedRevocationInfo(h1,t1)
		then:
		!hr1.hasExtension
		serializeToHex(hr1) == "0102030405060708091000001b58"
		when:
		HashBasedRevocationInfo hr2 = deserializeFromHex(new HashBasedRevocationInfo(), "0102030405060708091000001b58")
		then:
		!hr2.hasExtension
		hr2.getId() == h1
		hr2.getExpiry() == t1
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new HashBasedRevocationInfo(null,t1)
		then:
		thrown IOException
		when:
		new HashBasedRevocationInfo(h1,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new HashBasedRevocationInfo(h1,t1).toString() == """HashBasedRevocationInfo [id=[01020304050607080910], expiry=[timeStamp=Thu Jan 01 02:56:40 CET 2004 (7000)]]"""
	}
	

}
