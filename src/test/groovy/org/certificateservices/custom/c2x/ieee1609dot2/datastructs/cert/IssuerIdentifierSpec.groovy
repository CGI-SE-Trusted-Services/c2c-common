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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for IssuerIdentifier
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class IssuerIdentifierSpec extends BaseStructSpec {
	
	@Shared HashedId8 h = new HashedId8("SomeHostname".bytes)
	@Shared HashAlgorithm hashAlg = HashAlgorithm.sha256
		
	@Unroll
	def "Verify that IssuerIdentifier is correctly encoded for type #choice"(){
		when:
		def id = new IssuerIdentifier(value)
		
		then:
		serializeToHex(id) == encoding
		
		when:
		IssuerIdentifier id2 = deserializeFromHex(new IssuerIdentifier(), encoding)
		
		then:
		
		id2.choice == choice
		id2.type == choice
		if(id2.type == IssuerIdentifierChoices.self){
			id2.getHashAlgoritm() == value
		}else{
		  id2.getValue() == value
		}
		
		where:
		choice                                              | value                 | encoding   
		IssuerIdentifierChoices.sha256AndDigest             | h                     | "80486f73746e616d65"   
		IssuerIdentifierChoices.self                        | hashAlg               | "8100"
		
	}

	
	def "Verify toString"(){
		expect:
		new IssuerIdentifier(h).toString() == "IssuerIdentifier [sha256AndDigest=[486f73746e616d65]]"
		new IssuerIdentifier(hashAlg).toString() == "IssuerIdentifier [self=sha256]"

	}
	

}
