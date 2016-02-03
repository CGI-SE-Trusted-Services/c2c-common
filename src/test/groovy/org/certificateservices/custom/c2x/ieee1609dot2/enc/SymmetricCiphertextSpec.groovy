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
package org.certificateservices.custom.c2x.ieee1609dot2.enc

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext.SymmetricCiphertextChoices;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SymmetricCiphertext
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SymmetricCiphertextSpec extends BaseStructSpec {
	
	@Shared byte[] nounce = Hex.decode("010203040506070809101112")
	@Shared byte[] ccmCiphertext = Hex.decode("11121314")
	@Shared AesCcmCiphertext acc = new AesCcmCiphertext(nounce,ccmCiphertext)
	
	@Unroll
	def "Verify that SymmetricCiphertext is correctly encoded for type #choice"(){
		when:
		def o = new SymmetricCiphertext(value)
		
		then:
		serializeToHex(o) == encoding
		
		when:
		SymmetricCiphertext o2 = deserializeFromHex(new SymmetricCiphertext(), encoding)
		
		then:
		o2.getValue() == value
		o2.choice == choice
		o2.type == choice
		
		where:
		choice                                              | value                 | encoding   
		SymmetricCiphertextChoices.aes128ccm                | acc                   | "800102030405060708091011120411121314"   
		
	}

	
	def "Verify SymmetricCiphertext"(){
		expect:
		new SymmetricCiphertext(acc).toString() == "SymmetricCiphertext [aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]"
		
		
	}
	

}
