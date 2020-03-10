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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType.CrlContentsTypeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContents;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlPriorityInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedLinkageValueCrl;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlContents
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlContentsSpec extends BaseStructSpec {

	
	SequenceOfJMaxGroup individual = new SequenceOfJMaxGroup([SequenceOfJMaxGroupSpec.genJMaxGroup(7),SequenceOfJMaxGroupSpec.genJMaxGroup(8)])
	ToBeSignedLinkageValueCrl tbsl = new ToBeSignedLinkageValueCrl(5,6, individual, null)
	
	CrlSeries crlSeries = new CrlSeries(7)
	HashedId8  crlCraca = new HashedId8(Hex.decode("0102030405060708"))
	Time32 issueDate = new Time32(4000)
	Time32  nextCrl = new Time32(8000)
	CrlPriorityInfo priorityInfo = new CrlPriorityInfo(new Uint8(8))
	CrlContentsType typeSpecific = new CrlContentsType(CrlContentsTypeChoices.fullLinkedCrl, tbsl)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CrlContents cc1 = new CrlContents(crlSeries,crlCraca,issueDate,nextCrl,priorityInfo,typeSpecific)
		then:
		!cc1.hasExtension
		serializeToHex(cc1) == "010007010203040506070800000fa000001f40400882400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		when:
		CrlContents cc2 = deserializeFromHex(new CrlContents(), "010007010203040506070800000fa000001f40400882400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526")
		then:
		!cc2.hasExtension
		cc2.getVersion() == CrlContents.DEFAULT_VERSION
		cc2.getCrlSeries() == crlSeries
		cc2.getCrlCraca()== crlCraca
		cc2.getIssueDate() == issueDate
		cc2.getNextCrl() == nextCrl
		cc2.getPriorityInfo() == priorityInfo
		cc2.getTypeSpecific() == typeSpecific
		
		when:
		CrlContents cc3 = new CrlContents(7,crlSeries,crlCraca,issueDate,nextCrl,priorityInfo,typeSpecific)
		then:
		serializeToHex(cc3) == "070007010203040506070800000fa000001f40400882400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		when:
		CrlContents cc4 = deserializeFromHex(new CrlContents(), "070007010203040506070800000fa000001f40400882400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526")
		then:
		cc4.getVersion() == 7
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new CrlContents(null,crlCraca,issueDate,nextCrl,priorityInfo,typeSpecific)
		then:
		thrown IOException
		when:
		new CrlContents(crlSeries,null,issueDate,nextCrl,priorityInfo,typeSpecific)
		then:
		thrown IOException
		when:
		new CrlContents(crlSeries,crlCraca,null,nextCrl,priorityInfo,typeSpecific)
		then:
		thrown IOException
		when:
		new CrlContents(crlSeries,crlCraca,issueDate,null,priorityInfo,typeSpecific)
		then:
		thrown IOException
		when:
		new CrlContents(crlSeries,crlCraca,issueDate,nextCrl,null,typeSpecific)
		then:
		thrown IOException
		when:
		new CrlContents(crlSeries,crlCraca,issueDate,nextCrl,priorityInfo,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new CrlContents(crlSeries,crlCraca,issueDate,nextCrl,priorityInfo,typeSpecific).toString() == """CrlContents [
  version=1,
  crlSeries=[7],
  crlCraca= [0102030405060708],
  issueDate=[timeStamp=Thu Jan 01 02:06:40 CET 2004 (4000)],
  nextCrl=[timeStamp=Thu Jan 01 03:13:20 CET 2004 (8000)],
  priorityInfo=[priority=8],
  typeSpecific=[fullLinkedCrl=[iRev=5, indexWithinI=6,
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
  ]]
]"""
	}
	

}
