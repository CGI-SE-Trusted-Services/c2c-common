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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.IMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.IndividualRevocation;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.LAGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfIMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfIndividualRevocation;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for LAGroup
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class LAGroupSpec extends BaseStructSpec {

	LaId laid1 = new LaId(Hex.decode("0102"))
	LaId laid2 = new LaId(Hex.decode("0305"))
	
	LinkageSeed ls1_1_1 = new LinkageSeed(Hex.decode("01020304050607080910111213141516"))
	LinkageSeed ls2_1_1 = new LinkageSeed(Hex.decode("11121314151617181911212223242526"))
	LinkageSeed ls1_2_1 = new LinkageSeed(Hex.decode("21020304050607080910111213141516"))
	LinkageSeed ls2_2_1 = new LinkageSeed(Hex.decode("21121314151617181911212223242526"))
	
	
	IndividualRevocation ir1_1 = new IndividualRevocation( ls1_1_1, ls2_1_1)
	IndividualRevocation ir2_1 = new IndividualRevocation( ls1_2_1, ls2_2_1)
	
	LinkageSeed ls1_1_2 = new LinkageSeed(Hex.decode("21020304050607080910111213141516"))
	LinkageSeed ls2_1_2 = new LinkageSeed(Hex.decode("21121314151617181911212223242526"))
	LinkageSeed ls1_2_2 = new LinkageSeed(Hex.decode("31020304050607080910111213141516"))
	LinkageSeed ls2_2_2 = new LinkageSeed(Hex.decode("31121314151617181911212223242526"))
	
	
	IndividualRevocation ir1_2 = new IndividualRevocation( ls1_1_2, ls2_1_2)
	IndividualRevocation ir2_2 = new IndividualRevocation( ls1_2_2, ls2_2_2)
	
	IMaxGroup img1 = new IMaxGroup(7, new SequenceOfIndividualRevocation(ir1_1,ir2_1))
	IMaxGroup img2 = new IMaxGroup(8, new SequenceOfIndividualRevocation(ir1_2,ir2_2))
	
	SequenceOfIMaxGroup contents = new SequenceOfIMaxGroup([img1,img2])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		LAGroup lag1 = new LAGroup(laid1,laid2,contents)
		then:
		!lag1.hasExtension
		serializeToHex(lag1) == "01020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		when:
		LAGroup lag2 = deserializeFromHex(new LAGroup(), "01020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526")
		then:
		!lag2.hasExtension
		lag2.getLa1Id() == laid1
		lag2.getLa2Id() == laid2
		lag2.getContents() == contents
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new LAGroup(null,laid2,contents)
		then:
		thrown IllegalArgumentException
		when:
		new LAGroup(laid1,null,contents)
		then:
		thrown IllegalArgumentException
		when:
		new LAGroup(laid1,laid2,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new LAGroup(laid1,laid2,contents).toString() == """LAGroup [la1Id=[0102], la2Id=[0305], contents=[
    [imax=7, contents=[
        [linkage-seed1=[01020304050607080910111213141516], linkage-seed2=[11121314151617181911212223242526]],
        [linkage-seed1=[21020304050607080910111213141516], linkage-seed2=[21121314151617181911212223242526]]
      ]
    ],
    [imax=8, contents=[
        [linkage-seed1=[21020304050607080910111213141516], linkage-seed2=[21121314151617181911212223242526]],
        [linkage-seed1=[31020304050607080910111213141516], linkage-seed2=[31121314151617181911212223242526]]
      ]
    ]
  ]
]"""
	}
	

}
