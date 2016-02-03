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
package org.certificateservices.custom.c2x.ieee1609dot2.crl.secenv

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Opaque
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlPsid
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlPsidSpec extends BaseStructSpec {

	
   
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CrlPsid cp1 = new CrlPsid()
		then:
		serializeToHex(cp1) == "0124"
		when:
		CrlPsid cp2 = deserializeFromHex(new CrlPsid(), "0124")
		then:
		cp2.getValueAsLong() == CrlPsid.PSID
	}
	


	def "Verify toString"(){
		expect:
		new CrlPsid().toString() == """CrlPsid [36(24)]"""
	}
	

}
