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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Elevation
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SequenceOfRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Countersignature
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CountersignatureSpec extends BaseStructSpec {

	HashedId3 cracaid = new HashedId3(Hex.decode("010203040506070809101112"))
	CrlSeries crlSeries =new CrlSeries(100)
	byte[] k = COEREncodeHelper.padZerosToByteArray(Hex.decode("0100"),16);
	SymmetricEncryptionKey symmkey = new SymmetricEncryptionKey(SymmetricEncryptionKeyChoices.aes128Ccm,k)
	
	Psid psid = new Psid(64)
	Time64 generationTime = new Time64(BigInteger.valueOf(5000000L))
	Time64 expiryTime = new Time64(BigInteger.valueOf(6000000L))
	ThreeDLocation generationLocation = new ThreeDLocation(new Latitude(50),new Longitude(100),new Elevation(55))
	HashedId3 p2pcdLearningRequest = new HashedId3(Hex.decode("010203040506070809101112"))
	MissingCrlIdentifier missingCrlIdentifier =  new MissingCrlIdentifier(cracaid,crlSeries)
	EncryptionKey encryptionKey = new EncryptionKey(symmkey)
	
	Opaque o = new Opaque(Hex.decode("0102030405060708"))
	Ieee1609Dot2Content content = new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o)
	Ieee1609Dot2Data data = new Ieee1609Dot2Data(content)
	HashedData extHash = new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132"))
	SignedDataPayload sdp = new SignedDataPayload(data, extHash)
	
	Ieee1609Dot2Data valid = genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, null, null))
	
	def "Verify that fullfillsRequirements verifies all required fields"(){
		expect:
		!Countersignature.fullfillsRequirements(genUnsecured())
		!Countersignature.fullfillsRequirements(genSignedCertificateRequest())
		!Countersignature.fullfillsRequirements(genEncryptedData())
		Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(data, extHash), new HeaderInfo(psid, generationTime, null, null, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(data, null), new HeaderInfo(psid, generationTime, null, null, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, null, null, null, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, expiryTime, null, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, generationLocation, null, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, p2pcdLearningRequest, null, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, missingCrlIdentifier, null)))
		!Countersignature.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, null, encryptionKey)))
		
	}
	
	def "Verify that constructor throws Exception if content doesn't fullfill requirements"(){
		when:
		new Countersignature(genUnsecured().getContent())
		then:
		thrown IllegalArgumentException
		when:
		new Countersignature(4,genUnsecured().getContent())
		then:
		thrown IllegalArgumentException
		when:
		new Countersignature(genUnsecured())
		then:
		thrown IllegalArgumentException
		when:
		new Countersignature(genUnsecured().encoded)
		then:
		thrown IOException
		
	}
	
	def "Verify that constructor contains Ieee1609Dot2Data  if content  fullfill requirements"(){
		
		when:
		Countersignature c1 = new Countersignature(valid.content)
		then:
		c1.getContent() == valid.content
		when:
		Countersignature c2 =new Countersignature(4,valid.content)
		then:
		c2.getContent() == valid.content
		when:
		Countersignature c3 =new Countersignature(valid)
		then:
		c3.getContent() == valid.content
		when:
		Countersignature c4 =new Countersignature(valid.encoded)
		then:
		c4.getContent() == valid.content
		
	}

	def "Verify toString"(){
		expect:
		new Countersignature(valid).toString() == """Countersignature [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
        ],
        headerInfo=[
          psid=[64(40)],
          generationTime=[timeStamp=Thu Jan 01 01:00:05 CET 2004 (5000000)]
        ]
      ],
      signer=[digest=0102030405060708],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
    ]
  ]
]"""
	}
	
	
	private Ieee1609Dot2Data genUnsecured(){
		return new Ieee1609Dot2Data(new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData, new Opaque(Hex.decode("0102030405060708"))))
	}
	
	private Ieee1609Dot2Data genSignedCertificateRequest(){
		return new Ieee1609Dot2Data(new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.signedCertificateRequest , new Opaque(Hex.decode("0102030405060708"))))
	}
	
	private Ieee1609Dot2Data genEncryptedData(){
		RecipientInfo ri1 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))
		RecipientInfo ri2 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("1112131415161718")))
		byte[] nounce = Hex.decode("010203040506070809101112")
		byte[] ccmCiphertext = Hex.decode("11121314")
		SequenceOfRecipientInfo sri = new SequenceOfRecipientInfo([ri1,ri2])
		SymmetricCiphertext sct = new SymmetricCiphertext(new AesCcmCiphertext(nounce,ccmCiphertext))
		
		return new Ieee1609Dot2Data(new Ieee1609Dot2Content(new EncryptedData(sri,sct)))
	}
	
	private Ieee1609Dot2Data genSignedData(SignedDataPayload payload, HeaderInfo hi){
		HashedId8 h = new HashedId8(Hex.decode("0102030405060708"))
		SignerIdentifier signer = new SignerIdentifier(h)
		ToBeSignedData tbsData = new ToBeSignedData(payload,hi)
		
		byte[] x = new BigInteger(123).toByteArray()
		EccP256CurvePoint r = new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x)
		byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
		Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))
		
		return new Ieee1609Dot2Data(new Ieee1609Dot2Content(new SignedData(HashAlgorithm.sha256, tbsData, signer, signature)))
	}
	


}
