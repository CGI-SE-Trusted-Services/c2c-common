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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EciesP256EncryptedKey
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
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext.SymmetricCiphertextChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EncryptedDataEncryptionKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EncryptedDataEncryptionKeySpec extends BaseStructSpec {
	
	@Shared 	byte[] x = new BigInteger(123).toByteArray()
	@Shared EccP256CurvePoint v = new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x)
	@Shared byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
	@Shared byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
	@Shared EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)
	
	@Unroll
	def "Verify that EncryptedDataEncryptionKey is correctly encoded for type #choice"(){
		when:
		def o = new EncryptedDataEncryptionKey(choice,value)
		
		then:
		serializeToHex(o) == encoding
		
		when:
		EncryptedDataEncryptionKey o2 = deserializeFromHex(new EncryptedDataEncryptionKey(), encoding)
		
		then:
		o2.getValue() == value
		o2.choice == choice
		o2.type == choice
		
		where:
		choice                                                   | value                 | encoding
		EncryptedDataEncryptionKeyChoices.eciesNistP256          | encKey                | "8080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		EncryptedDataEncryptionKeyChoices.eciesBrainpoolP256r1   | encKey                | "8180000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		
		
	}

	
	def "Verify EncryptedDataEncryptionKey"(){
		expect:
		new EncryptedDataEncryptionKey(EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey).toString() == "EncryptedDataEncryptionKey [eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]"
		
		
	}
	

}
