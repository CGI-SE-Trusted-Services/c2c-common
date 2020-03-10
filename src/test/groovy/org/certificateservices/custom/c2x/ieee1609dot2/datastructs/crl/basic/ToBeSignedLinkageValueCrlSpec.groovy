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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.GroupCrlEntry;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfGroupCrlEntry;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedLinkageValueCrl;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ToBeSignedLinkageValueCrl
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class ToBeSignedLinkageValueCrlSpec extends BaseStructSpec {

	LaId laid1 = new LaId(Hex.decode("0102"))
	LinkageSeed ls1 = new LinkageSeed(Hex.decode("01020304050607080910111213141516"))
	LaId laid2 = new LaId(Hex.decode("0305"))
	LinkageSeed ls2 = new LinkageSeed(Hex.decode("11121314151617181911212223242526"))
	
	GroupCrlEntry gce1 = new GroupCrlEntry(4, laid1, ls1, laid2, ls2)
	GroupCrlEntry gce2 = new GroupCrlEntry(6, laid1, ls1, laid2, ls2)
	
	SequenceOfJMaxGroup individual = new SequenceOfJMaxGroup([SequenceOfJMaxGroupSpec.genJMaxGroup(7),SequenceOfJMaxGroupSpec.genJMaxGroup(8)])
	SequenceOfGroupCrlEntry groups = new SequenceOfGroupCrlEntry([gce1,gce2])
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		ToBeSignedLinkageValueCrl tbs1 = new ToBeSignedLinkageValueCrl(9,6,individual,groups)
		then:
		gce1.hasExtension
		serializeToHex(tbs1) == "6000090601020007010201020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526110213050102000007010200010203040506070809101112131415161112131415161718191121222324252600210203040506070809101112131415162112131415161718191121222324252600000801020021020304050607080910111213141516211213141516171819112122232425260031020304050607080910111213141516311213141516171819112122232425260008010201020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526110213050102000007010200010203040506070809101112131415161112131415161718191121222324252600210203040506070809101112131415162112131415161718191121222324252600000801020021020304050607080910111213141516211213141516171819112122232425260031020304050607080910111213141516311213141516171819112122232425260102000004010201020304050607080910111213141516030511121314151617181911212223242526000006010201020304050607080910111213141516030511121314151617181911212223242526"
		when:
		ToBeSignedLinkageValueCrl tbs2 = deserializeFromHex(new ToBeSignedLinkageValueCrl(), "6000090601020007010201020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526110213050102000007010200010203040506070809101112131415161112131415161718191121222324252600210203040506070809101112131415162112131415161718191121222324252600000801020021020304050607080910111213141516211213141516171819112122232425260031020304050607080910111213141516311213141516171819112122232425260008010201020305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526110213050102000007010200010203040506070809101112131415161112131415161718191121222324252600210203040506070809101112131415162112131415161718191121222324252600000801020021020304050607080910111213141516211213141516171819112122232425260031020304050607080910111213141516311213141516171819112122232425260102000004010201020304050607080910111213141516030511121314151617181911212223242526000006010201020304050607080910111213141516030511121314151617181911212223242526")
		then:
		tbs1.hasExtension
		tbs1.getIRev() == 9
		tbs1.getIndexWithinI() == 6
		tbs1.getIndividual() == individual
		tbs1.getGroups() == groups
		
		when:
		ToBeSignedLinkageValueCrl tbs3 = new ToBeSignedLinkageValueCrl(9,6,individual,null)
		then:
		gce1.hasExtension
		serializeToHex(tbs3) == "400009060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		when:
		ToBeSignedLinkageValueCrl tbs4 = deserializeFromHex(new ToBeSignedLinkageValueCrl(), "400009060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526")
		then:
		tbs4.hasExtension
		tbs4.getIRev() == 9
		tbs4.getIndexWithinI() == 6
		tbs4.getIndividual() == individual
		tbs4.getGroups() == null
		
		when:
		ToBeSignedLinkageValueCrl tbs5 = new ToBeSignedLinkageValueCrl(9,6,null,groups)
		then:
		gce1.hasExtension
		serializeToHex(tbs5) == "200009060102000004010201020304050607080910111213141516030511121314151617181911212223242526000006010201020304050607080910111213141516030511121314151617181911212223242526"
		when:
		ToBeSignedLinkageValueCrl tbs6 = deserializeFromHex(new ToBeSignedLinkageValueCrl(), "200009060102000004010201020304050607080910111213141516030511121314151617181911212223242526000006010201020304050607080910111213141516030511121314151617181911212223242526")
		then:
		tbs6.hasExtension
		tbs6.getIRev() == 9
		tbs6.getIndexWithinI() == 6
		tbs6.getIndividual() == null
		tbs6.getGroups() == groups
	}
	
	def "Verify that IOException is thrown if both individual and groups are null"(){
		when:
		new ToBeSignedLinkageValueCrl(6, 3,null,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new ToBeSignedLinkageValueCrl(9,6,individual,groups).toString() == """ToBeSignedLinkageValueCrl [iRev=9, indexWithinI=6,
  individual=[
    [imax=7, contents=[
        [la1Id=[0102], la2Id=[0305], contents=[
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
        ],
        [la1Id=[1102], la2Id=[1305], contents=[
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
        ]
      ]
    ],
    [imax=8, contents=[
        [la1Id=[0102], la2Id=[0305], contents=[
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
        ],
        [la1Id=[1102], la2Id=[1305], contents=[
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
        ]
      ]
    ]
  ],
  groups=SequenceOfGroupCrlEntry [
    [iMax=4, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]],
    [iMax=6, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]]
  ]
]"""
		new ToBeSignedLinkageValueCrl(9,6,individual,null).toString() == """ToBeSignedLinkageValueCrl [iRev=9, indexWithinI=6,
  individual=[
    [imax=7, contents=[
        [la1Id=[0102], la2Id=[0305], contents=[
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
        ],
        [la1Id=[1102], la2Id=[1305], contents=[
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
        ]
      ]
    ],
    [imax=8, contents=[
        [la1Id=[0102], la2Id=[0305], contents=[
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
        ],
        [la1Id=[1102], la2Id=[1305], contents=[
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
        ]
      ]
    ]
  ]
]"""
		new ToBeSignedLinkageValueCrl(9,6,null,groups).toString() == """ToBeSignedLinkageValueCrl [iRev=9, indexWithinI=6,
  groups=SequenceOfGroupCrlEntry [
    [iMax=4, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]],
    [iMax=6, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]]
  ]
]"""
	}
	

}
