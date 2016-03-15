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

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext.SymmetricCiphertextChoices;

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
	
	
	@Shared EccP256CurvePoint v = new EccP256CurvePoint(new BigInteger(123))
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
