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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SequenceOfRecipientInfo;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfRecipientInfo class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfRecipientInfoSpec extends BaseStructSpec {

	RecipientInfo ri1 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))
	RecipientInfo ri2 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("1112131415161718")))
	
	def "Verify that SequenceOfRecipientInfo is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfRecipientInfo(),"0102800102030405060708801112131415161718")
		then:
		u1.getSequenceValues()[0] == ri1
		u1.getSequenceValues()[1] == ri2
		when:
		def u2 = new SequenceOfRecipientInfo([ri1,ri2] as RecipientInfo[])
		then:
		u2.getSequenceValues()[0] == ri1
		u2.getSequenceValues()[1] == ri2
		
		when:
		def u3 = new SequenceOfRecipientInfo([ri1,ri2])
		then:
		u3.getSequenceValues()[0] == ri1
		u3.getSequenceValues()[1] == ri2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfRecipientInfo([ri1,ri2]).toString() == "SequenceOfRecipientInfo [[pskRecipInfo=[0102030405060708]],[pskRecipInfo=[1112131415161718]]]"
		new SequenceOfRecipientInfo().toString() == "SequenceOfRecipientInfo []"
		new SequenceOfRecipientInfo([ri1]).toString() == "SequenceOfRecipientInfo [[pskRecipInfo=[0102030405060708]]]"
		
	
	}
	

	


}
