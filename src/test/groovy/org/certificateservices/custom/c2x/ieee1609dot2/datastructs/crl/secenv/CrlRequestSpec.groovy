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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.CrlRequest;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlRequest
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlRequestSpec extends BaseStructSpec {

	
    Opaque content = new Opaque(Hex.decode("01020304050607080910111213141516"))
	
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CrlRequest cr1 = new CrlRequest(content)
		then:
		cr1.hasExtension
		serializeToHex(cr1) == "001001020304050607080910111213141516"
		when:
		CrlRequest cr2 = deserializeFromHex(new CrlRequest(), "001001020304050607080910111213141516")
		then:
		cr2.hasExtension
		cr2.getContent() == content
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new CrlRequest(null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new CrlRequest(content).toString() == """CrlRequest [content=[data=01020304050607080910111213141516]]"""
	}
	

}
