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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlPriorityInfo;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlPriorityInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlPriorityInfoSpec extends BaseStructSpec {

	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CrlPriorityInfo cp1 = new CrlPriorityInfo(new Uint8(4))
		then:
		cp1.hasExtension
		serializeToHex(cp1) == "4004"
		when:
		CrlPriorityInfo cp2 = deserializeFromHex(new CrlPriorityInfo(), "4004")
		then:
		cp2.hasExtension
		cp2.getPriority().getValueAsLong() == 4
		when:
		CrlPriorityInfo cp3 = new CrlPriorityInfo(null)
		then:
		serializeToHex(cp3) == "00"
		when:
		CrlPriorityInfo cp4 = deserializeFromHex(new CrlPriorityInfo(), "00")
		then:
		cp4.getPriority() == null		
	}
	
 
	

	def "Verify toString"(){
		expect:
		new CrlPriorityInfo(new Uint8(4)).toString() == """CrlPriorityInfo [priority=4]"""
	}
	

}
