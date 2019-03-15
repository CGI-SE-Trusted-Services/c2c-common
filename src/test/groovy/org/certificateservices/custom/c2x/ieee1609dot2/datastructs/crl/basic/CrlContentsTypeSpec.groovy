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

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId10;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType.CrlContentsTypeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.HashBasedRevocationInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfHashBasedRevocationInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedHashIdCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedLinkageValueCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext.SymmetricCiphertextChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.p2p.Ieee1609dot2Peer2PeerPDUContent.Ieee1609dot2Peer2PeerPDUContentChoices;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlContentsType
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CrlContentsTypeSpec extends BaseStructSpec {
	
	@Shared HashedId10 h1 = new HashedId10(Hex.decode("01020304050607080910"))
	@Shared HashedId10 h2 = new HashedId10(Hex.decode("11121314051617181920"))
	
	@Shared Time32 t1 = new Time32(7000)
	@Shared Time32 t2 = new Time32(9000)
	
	@Shared HashBasedRevocationInfo hr1 = new HashBasedRevocationInfo(h1,t1)
	@Shared HashBasedRevocationInfo hr2 = new HashBasedRevocationInfo(h2,t2)
	
	@Shared SequenceOfHashBasedRevocationInfo entries = new SequenceOfHashBasedRevocationInfo([hr1,hr2])
	
	@Shared SequenceOfJMaxGroup individual = new SequenceOfJMaxGroup([SequenceOfJMaxGroupSpec.genJMaxGroup(7),SequenceOfJMaxGroupSpec.genJMaxGroup(8)])
	
	@Shared ToBeSignedHashIdCrl tbsh = new ToBeSignedHashIdCrl(3, entries)
	@Shared ToBeSignedLinkageValueCrl tbsl = new ToBeSignedLinkageValueCrl(5,6, individual, null)
	
	@Unroll
	def "Verify that CrlContentsType is correctly encoded for type #choice"(){
		when:
		def o = new CrlContentsType(choice, value)
		
		then:
		serializeToHex(o) == encoding
		
		when:
		CrlContentsType o2 = deserializeFromHex(new CrlContentsType(), encoding)
		
		then:
		o2.getValue() == value
		o2.choice == choice
		o2.type == choice
		!choice.extension
		
		where:
		choice                                       | value                            | encoding   
		CrlContentsTypeChoices.fullHashCrl           | tbsh                             | "80000000000301020102030405060708091000001b581112131405161718192000002328"
		CrlContentsTypeChoices.deltaHashCrl          | tbsh                             | "81000000000301020102030405060708091000001b581112131405161718192000002328"
		CrlContentsTypeChoices.fullLinkedCrl         | tbsl                             | "82400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		CrlContentsTypeChoices.deltaLinkedCrl        | tbsl                             | "83400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526"
		
	}

	
	def "Verify toString()"(){
		expect:
		 new CrlContentsType(CrlContentsTypeChoices.fullHashCrl, tbsh).toString() == """CrlContentsType [fullHashCrl=[
  crlSerial=3,
  entries=[
    [id=[01020304050607080910], expiry=[timeStamp=Thu Jan 01 02:56:40 CET 2004 (7000)]],
    [id=[11121314051617181920], expiry=[timeStamp=Thu Jan 01 03:30:00 CET 2004 (9000)]]
  ]
]]"""
  new CrlContentsType(CrlContentsTypeChoices.fullLinkedCrl, tbsl).toString() == """CrlContentsType [fullLinkedCrl=[iRev=5, indexWithinI=6,
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
]]"""
		
		
		
	}
	

}
