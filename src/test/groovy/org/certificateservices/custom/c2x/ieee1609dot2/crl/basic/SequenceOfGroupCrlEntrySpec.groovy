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
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SequenceOfGroupCrlEntry
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfGroupCrlEntrySpec extends BaseStructSpec {

	LaId laid1 = new LaId(Hex.decode("0102"))
	LinkageSeed ls1 = new LinkageSeed(Hex.decode("01020304050607080910111213141516"))
	LaId laid2 = new LaId(Hex.decode("0305"))
	LinkageSeed ls2 = new LinkageSeed(Hex.decode("11121314151617181911212223242526"))
	
	GroupCrlEntry gce1 = new GroupCrlEntry(4, laid1, ls1, laid2, ls2)
	GroupCrlEntry gce2 = new GroupCrlEntry(6, laid1, ls1, laid2, ls2)
	
	def "Verify that SequenceOfGroupCrlEntry is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfGroupCrlEntry(),"0102000004010201020304050607080910111213141516030511121314151617181911212223242526000006010201020304050607080910111213141516030511121314151617181911212223242526")
		then:
		u1.getSequenceValues()[0] == gce1
		u1.getSequenceValues()[1] == gce2
		when:
		def u2 = new SequenceOfGroupCrlEntry([gce1,gce2] as GroupCrlEntry[])
		then:
		u2.getSequenceValues()[0] == gce1
		u2.getSequenceValues()[1] == gce2
		
		when:
		def u3 = new SequenceOfGroupCrlEntry([gce1,gce2])
		then:
		u3.getSequenceValues()[0] == gce1
		u3.getSequenceValues()[1] == gce2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfGroupCrlEntry([gce1,gce2]).toString() == """SequenceOfGroupCrlEntry [
  [iMax=4, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]],
  [iMax=6, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]]
]"""
		new SequenceOfGroupCrlEntry().toString() == "SequenceOfGroupCrlEntry []"
		new SequenceOfGroupCrlEntry([gce1]).toString() == """SequenceOfGroupCrlEntry [
  [iMax=4, la1Id=[0102], linkageSeed1=[01020304050607080910111213141516], la2Id=[0305], linkageSeed2=[11121314151617181911212223242526]]
]"""
		
	
	}
	

	
	


}
