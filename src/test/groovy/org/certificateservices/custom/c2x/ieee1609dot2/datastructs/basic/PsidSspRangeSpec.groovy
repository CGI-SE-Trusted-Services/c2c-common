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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PsidSspRange
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PsidSspRangeSpec extends BaseStructSpec {

	Psid psid = new Psid(123)
	SspRange ssprange = new SspRange(SspRangeChoices.all, null)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PsidSspRange p1 = new PsidSspRange(psid,ssprange)
		then:
		serializeToHex(p1) == "80017b81"
		when:
		PsidSspRange p2 = deserializeFromHex(new PsidSspRange(), "80017b81")
		then:
		p2.getSSPRange() == ssprange
		p2.getPsid() == psid
		when:
		PsidSspRange p3 = new PsidSspRange(psid,null)
		then:
		serializeToHex(p3) == "00017b"
		when:
		PsidSspRange p4 = deserializeFromHex(new PsidSspRange(), "00017b")
		then:
		p4.getSSPRange() == null
		p4.getPsid() == psid
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new PsidSspRange(null,ssprange)
		then:
		thrown IOException
	} 
	

	
	def "Verify toString"(){
		expect:
		new PsidSspRange(psid,ssprange).toString() == "PsidSspRange [psid=[123(7b)], sspRange=[all]]"
		new PsidSspRange(psid,null).toString() == "PsidSspRange [psid=[123(7b)], sspRange=NULL]"
	}
	

}
