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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8;
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
import static org.certificateservices.custom.c2x.ieee1609dot2.enc.RecipientInfo.RecipientInfoChoices.*

/**
 * Test for RecipientInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class RecipientInfoSpec extends BaseStructSpec {
	

	@Shared PreSharedKeyRecipientInfo kRI = new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708"))
	
	
	@Shared byte[] nounce = Hex.decode("010203040506070809101112")
	@Shared byte[] ccmCiphertext = Hex.decode("11121314")
	@Shared AesCcmCiphertext acc = new AesCcmCiphertext(nounce,ccmCiphertext)
	@Shared SymmRecipientInfo sRI = new SymmRecipientInfo(new HashedId8(Hex.decode("0102030405060708")),new SymmetricCiphertext(acc))
	
	@Shared byte[] x = new BigInteger(123).toByteArray()
	@Shared EccP256CurvePoint v = new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x)
	@Shared byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
	@Shared byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
	@Shared EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)
	
	@Shared PKRecipientInfo ri = new PKRecipientInfo(new HashedId8(Hex.decode("0102030405060708")), new EncryptedDataEncryptionKey(EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey))
	
	@Unroll
	def "Verify that RecipientInfo is correctly encoded for type #choice"(){
		when:
		def o = value
		
		then:
		serializeToHex(o) == encoding
		
		when:
		RecipientInfo o2 = deserializeFromHex(new RecipientInfo(), encoding)
		
		then:
		o2.getValue() == value.getValue()
		o2.choice == choice
		o2.type == choice
		
		where:
		choice                                                   | value                                     | encoding
		pskRecipInfo                                             | new RecipientInfo(kRI)                    | "800102030405060708"
		symmRecipInfo                                            | new RecipientInfo(sRI)                    | "810102030405060708800102030405060708091011120411121314"
		certRecipInfo                                            | new RecipientInfo(certRecipInfo,ri)       | "8201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		signedDataRecipInfo                                      | new RecipientInfo(signedDataRecipInfo,ri) | "8301020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		rekRecipInfo                                             | new RecipientInfo(rekRecipInfo,ri)        | "8401020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		
	}

	
	def "Verify EncryptedDataEncryptionKey"(){
		expect:
		new RecipientInfo(kRI).toString() == "RecipientInfo [pskRecipInfo=[0102030405060708]]"
		new RecipientInfo(sRI).toString() == "RecipientInfo [symmRecipInfo=[recipientId=[0102030405060708], encKey=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]]]"
		new RecipientInfo(certRecipInfo,ri).toString() == "RecipientInfo [certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]"
		new RecipientInfo(signedDataRecipInfo,ri).toString() == "RecipientInfo [signedDataRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]"
		new RecipientInfo(rekRecipInfo,ri) .toString() == "RecipientInfo [rekRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]"
	}
	

}
