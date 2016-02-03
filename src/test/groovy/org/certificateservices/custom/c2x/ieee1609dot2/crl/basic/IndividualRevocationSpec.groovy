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
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for IndividualRevocation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class IndividualRevocationSpec extends BaseStructSpec {

	
	LinkageSeed ls1 = new LinkageSeed(Hex.decode("01020304050607080910111213141516"))
	
	LinkageSeed ls2 = new LinkageSeed(Hex.decode("11121314151617181911212223242526"))
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		IndividualRevocation ir1 = new IndividualRevocation(ls1,ls2)
		then:
		ir1.hasExtension
		serializeToHex(ir1) == "000102030405060708091011121314151611121314151617181911212223242526"
		when:
		IndividualRevocation ir2 = deserializeFromHex(new IndividualRevocation(), "000102030405060708091011121314151611121314151617181911212223242526")
		then:
		ir2.hasExtension
		ir2.getLinkageSeed1() == ls1
		ir2.getLinkageSeed2() == ls2
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new IndividualRevocation(null,ls2)
		then:
		thrown IllegalArgumentException
		when:
		new IndividualRevocation(ls1,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new IndividualRevocation(ls1,ls2).toString() == """IndividualRevocation [linkage-seed1=[01020304050607080910111213141516], linkage-seed2=[11121314151617181911212223242526]]"""
	}
	

}
