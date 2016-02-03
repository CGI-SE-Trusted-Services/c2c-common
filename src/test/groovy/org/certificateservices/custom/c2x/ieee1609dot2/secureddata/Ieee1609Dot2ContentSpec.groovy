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
package org.certificateservices.custom.c2x.ieee1609dot2.secureddata

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Opaque
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateId.CertificateIdChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SequenceOfCertificateSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedData
import org.certificateservices.custom.c2x.ieee1609dot2.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SequenceOfRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.SignerIdentifier.SignerIdentifierChoices;
import org.junit.After;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for  Ieee1609Dot2Content
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class Ieee1609Dot2ContentSpec extends BaseStructSpec {
	
	

	@Shared RecipientInfo ri1 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))
	@Shared RecipientInfo ri2 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("1112131415161718")))
	
	@Shared SequenceOfRecipientInfo sri = new SequenceOfRecipientInfo([ri1,ri2])
	
	
	@Shared byte[] nounce = Hex.decode("010203040506070809101112")
	@Shared byte[] ccmCiphertext = Hex.decode("11121314")
	
	@Shared SymmetricCiphertext sct = new SymmetricCiphertext(new AesCcmCiphertext(nounce,ccmCiphertext))
	
	@Shared Opaque o = new Opaque(Hex.decode("0102030405060708"))
	@Shared EncryptedData e = new EncryptedData(sri,sct)
	
	@Shared SignedDataPayload sdp = new SignedDataPayload(null, new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")))
	@Shared HeaderInfo hi = new HeaderInfo(new Psid(100), null, null, null, null, null, null)
	@Shared ToBeSignedData tbsData = new ToBeSignedData(sdp,hi)
	
	@Shared HashedId8 h = new HashedId8(Hex.decode("0102030405060708"))
	@Shared SignerIdentifier signer = new SignerIdentifier(h)
	
	
	@Shared EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
	@Shared byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
	@Shared Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))
	
	@Shared SignedData sd = new SignedData(HashAlgorithm.sha256, tbsData, signer, signature)
	
	@Unroll
	def "Verify that  Ieee1609Dot2Content is correctly encoded for type #choice"(){
		when:
		def ic = value
		
		then:
		serializeToHex(ic) == encoding
		
		when:
		Ieee1609Dot2Content ic2 = deserializeFromHex(new  Ieee1609Dot2Content(), encoding)
		
		then:
		ic.getValue() == value.getValue()
		ic.choice == choice
		ic.type == choice
		
		where:
		choice                                              | value                                                                           | encoding   
		Ieee1609Dot2ContentChoices.unsecuredData            | new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o)             | "80080102030405060708"   
		Ieee1609Dot2ContentChoices.signedData               | new Ieee1609Dot2Content(sd)                                                     | "8100208001020304050607080910111213141516171819202122232425262728293031320001648001020304050607088080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		Ieee1609Dot2ContentChoices.encryptedData            | new Ieee1609Dot2Content(e)                                                      | "820102800102030405060708801112131415161718800102030405060708091011120411121314"
		Ieee1609Dot2ContentChoices.signedCertificateRequest | new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.signedCertificateRequest,o)  | "83080102030405060708"
	}

	
	def "Verify toString"(){
		expect:
		new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o) .toString() == """Ieee1609Dot2Content [
  unsecuredData=[data=0102030405060708]
]"""
		new Ieee1609Dot2Content(sd).toString() == """Ieee1609Dot2Content [
  signedData=[
    hashAlgorithm=sha256,
    tbsData=[
      payload=[
        extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
      ],
      headerInfo=[
        psid=[100(64)]
      ]
    ],
    signer=[digest=0102030405060708],
    signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
  ]
]"""
		new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.signedCertificateRequest,o).toString() == """Ieee1609Dot2Content [
  signedCertificateRequest=[data=0102030405060708]
]"""
	}
	

}
