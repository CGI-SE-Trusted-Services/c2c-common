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
 * Test for GroupCrlEntry
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class GroupCrlEntrySpec extends BaseStructSpec {

	LaId laid1 = new LaId(Hex.decode("0102"))
	LinkageSeed ls1 = new LinkageSeed(Hex.decode("01020304050607080910111213141516"))
	LaId laid2 = new LaId(Hex.decode("0305"))
	LinkageSeed ls2 = new LinkageSeed(Hex.decode("11121314151617181911212223242526"))
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		GroupCrlEntry gce1 = new GroupCrlEntry(5,laid1,ls1,laid2,ls2)
		then:
		gce1.hasExtension
		serializeToHex(gce1) == "000005010201020304050607080910111213141516030511121314151617181911212223242526"
		when:
		GroupCrlEntry gce2 = deserializeFromHex(new GroupCrlEntry(), "000005010201020304050607080910111213141516030511121314151617181911212223242526")
		then:
		gce2.hasExtension
		gce2.getIMax() == 5
		gce2.getLa1Id() == laid1
		gce2.getLinkageSeed1() == ls1
		gce2.getLa2Id() == laid2
		gce2.getLinkageSeed2() == ls2
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new GroupCrlEntry(1, null,ls1,laid2,ls2)
		then:
		thrown IllegalArgumentException
		when:
		new GroupCrlEntry(1,laid1,null,laid2,ls2)
		then:
		thrown IllegalArgumentException
		when:
		new GroupCrlEntry(1,laid1,ls1,null,ls2)
		then:
		thrown IllegalArgumentException
		when:
		new GroupCrlEntry(1,laid1,ls1,laid2,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new GroupCrlEntry(5,laid1,ls1,laid2,ls2).toString() == """GroupCrlEntry [iMax=5, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]]"""
	}
	

}
