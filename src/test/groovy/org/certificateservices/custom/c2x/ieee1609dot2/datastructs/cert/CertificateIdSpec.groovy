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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.LinkageData;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CertificateId
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CertificateIdSpec extends BaseStructSpec {
	
	@Shared Hostname n = new Hostname("SomeHostname")
	@Shared byte[] bId = "test".bytes
	@Shared LinkageData ld = new LinkageData(new IValue(5), new LinkageValue("012345678".bytes), null)
		
	@Unroll
	def "Verify that CertificateId is correctly encoded for type #choice"(){
		when:
		def id = value
		
		then:
		serializeToHex(id) == encoding
		
		when:
		CertificateId id2 = deserializeFromHex(new CertificateId(), encoding)
		
		then:
		id2.getValue() == value.getValue()
		id2.choice == choice
		id2.type == choice
		!choice.extension
		
		where:
		choice                                              | value                 | encoding   
		CertificateIdChoices.linkageData                    | new CertificateId(ld) | "80000005303132333435363738"   
		CertificateIdChoices.name                           | new CertificateId(n)  | "810c536f6d65486f73746e616d65"
		CertificateIdChoices.binaryId                       | new CertificateId(bId)| "820474657374"
		CertificateIdChoices.none                           | new CertificateId()   | "83"
	}

	
	def "Verify toString"(){
		expect:
		new CertificateId(ld).toString() == "CertificateId [linkageData=[iCert=[5], linkage-value=[303132333435363738], group-linkage-value=NULL]]"
		new CertificateId(n).toString() == "CertificateId [name=[SomeHostname]]"
		new CertificateId(bId).toString() == "CertificateId [binaryId=74657374]"
		new CertificateId().toString() == "CertificateId [none]"
	}
	

}
