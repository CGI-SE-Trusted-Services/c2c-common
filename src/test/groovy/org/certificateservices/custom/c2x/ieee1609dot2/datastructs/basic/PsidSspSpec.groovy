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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PsidSsp
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PsidSspSpec extends BaseStructSpec {

	Psid psid = new Psid(123)
	byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
	ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, sspData)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PsidSsp p1 = new PsidSsp(psid,ssp)
		then:
		serializeToHex(p1) == "80017b801e0000000000000000000000000000000000000000000000000000000000f5"
		when:
		PsidSsp p2 = deserializeFromHex(new PsidSsp(), "80017b801e0000000000000000000000000000000000000000000000000000000000f5")
		then:
		p2.getSSP() == ssp
		p2.getPsid() == psid
		when:
		PsidSsp p3 = new PsidSsp(psid,null)
		then:
		serializeToHex(p3) == "00017b"
		when:
		PsidSsp p4 = deserializeFromHex(new PsidSsp(), "00017b")
		then:
		p4.getSSP() == null
		p4.getPsid() == psid
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new PsidSsp(null,ssp)
		then:
		thrown IOException
	} 
	

	
	def "Verify toString"(){
		expect:
		new PsidSsp(psid,ssp).toString() == "PsidSsp [psid=[123(7b)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]"
		new PsidSsp(psid,null).toString() == "PsidSsp [psid=[123(7b)], ssp=NULL]"
	}
	

}
