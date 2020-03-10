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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Elevation
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContents;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContentsType.CrlContentsTypeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlPriorityInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroup;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.SequenceOfJMaxGroupSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.ToBeSignedLinkageValueCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.CrlPsid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.SecuredCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SequenceOfRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.MissingCrlIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.ToBeSignedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SecuredCrl
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SecuredCrlSpec extends BaseStructSpec {

	HashedId3 cracaid = new HashedId3(Hex.decode("010203040506070809101112"))
	CrlSeries crlSeries =new CrlSeries(100)
	byte[] k = COEREncodeHelper.padZerosToByteArray(Hex.decode("0100"),16);
	SymmetricEncryptionKey symmkey = new SymmetricEncryptionKey(SymmetricEncryptionKeyChoices.aes128Ccm,k)
	
	Psid psid = new CrlPsid();
	Psid invalidPsid = new Psid(64)
	Time64 generationTime = new Time64(BigInteger.valueOf(5000000L))
	Time64 expiryTime = new Time64(BigInteger.valueOf(6000000L))
	ThreeDLocation generationLocation = new ThreeDLocation(new Latitude(50),new Longitude(100),new Elevation(55))
	HashedId3 p2pcdLearningRequest = new HashedId3(Hex.decode("010203040506070809101112"))
	MissingCrlIdentifier missingCrlIdentifier =  new MissingCrlIdentifier(cracaid,crlSeries)
	EncryptionKey encryptionKey = new EncryptionKey(symmkey)
	
	SequenceOfJMaxGroup individual = new SequenceOfJMaxGroup([SequenceOfJMaxGroupSpec.genJMaxGroup(7),SequenceOfJMaxGroupSpec.genJMaxGroup(8)])
	ToBeSignedLinkageValueCrl tbsl = new ToBeSignedLinkageValueCrl(5,6, individual, null)
	
	Time32 issueDate = new Time32(4000)
	Time32  nextCrl = new Time32(8000)
	HashedId8  cracaIdInCrl = new HashedId8(Hex.decode("0102030405060708"))
	CrlPriorityInfo priorityInfo = new CrlPriorityInfo(new Uint8(8))
	CrlContentsType typeSpecific = new CrlContentsType(CrlContentsTypeChoices.fullLinkedCrl, tbsl)
	
	CrlContents crlContents = new CrlContents(crlSeries, cracaIdInCrl, issueDate, nextCrl, priorityInfo, typeSpecific)
	
	Opaque o = new Opaque(crlContents.encoded)
	Ieee1609Dot2Content content = new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o)
	Ieee1609Dot2Data data = new Ieee1609Dot2Data(content)
	HashedData extHash = new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132"))
	SignedDataPayload sdp = new SignedDataPayload(data, extHash)
	
	Ieee1609Dot2Data valid = genSignedData(new SignedDataPayload(data, null), new HeaderInfo(new CrlPsid(), null, null, null, null, null, null,null,null))
	
	def "Verify that fullfillsRequirements verifies all required fields"(){
		expect:
		!SecuredCrl.fullfillsRequirements(genUnsecured())
		!SecuredCrl.fullfillsRequirements(genSignedCertificateRequest())
		!SecuredCrl.fullfillsRequirements(genEncryptedData())
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, null, null, null, null, null, null,null,null)))
		 SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(data, extHash), new HeaderInfo(psid, null, null, null, null, null, null,null,null)))
		 SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(data, null), new HeaderInfo(psid, null, null, null, null, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(data, null), new HeaderInfo(invalidPsid, null, null, null, null, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, null, null, null, null, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, expiryTime, null, null, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, generationLocation, null, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, p2pcdLearningRequest, null, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, missingCrlIdentifier, null,null,null)))
		!SecuredCrl.fullfillsRequirements(genSignedData(new SignedDataPayload(null, extHash), new HeaderInfo(psid, generationTime, null, null, null, null, encryptionKey,null,null)))
		
	}
	
	def "Verify that constructor throws Exception if content doesn't fulfill requirements"(){
		when:
		new SecuredCrl(genUnsecured().getContent())
		then:
		thrown IOException
		when:
		new SecuredCrl(4,genUnsecured().getContent())
		then:
		thrown IOException
		when:
		new SecuredCrl(genUnsecured())
		then:
		thrown IOException
		when:
		new SecuredCrl(genUnsecured().encoded)
		then:
		thrown IOException
		
	}
	
	def "Verify that constructor contains Ieee1609Dot2Data  if content  fullfill requirements"(){
		
		when:
		SecuredCrl c1 = new SecuredCrl(valid.content)
		then:
		c1.getContent() == valid.content
		when:
		SecuredCrl c2 =new SecuredCrl(4,valid.content)
		then:
		c2.getContent() == valid.content
		when:
		SecuredCrl c3 =new SecuredCrl(valid)
		then:
		c3.getContent() == valid.content
		when:
		SecuredCrl c4 =new SecuredCrl(valid.encoded)
	
		then:
		c4.getContent() == valid.content
		
	}

	def "Verify toString"(){
		expect:
		new SecuredCrl(valid).toString() == """SecuredCrl [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              unsecuredData=[data=010064010203040506070800000fa000001f40400882400005060102000701020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526000801020102030501020000070102000102030405060708091011121314151611121314151617181911212223242526002102030405060708091011121314151621121314151617181911212223242526000008010200210203040506070809101112131415162112131415161718191121222324252600310203040506070809101112131415163112131415161718191121222324252611021305010200000701020001020304050607080910111213141516111213141516171819112122232425260021020304050607080910111213141516211213141516171819112122232425260000080102002102030405060708091011121314151621121314151617181911212223242526003102030405060708091011121314151631121314151617181911212223242526]
            ]
          ]
        ],
        headerInfo=[
          psid=Crl[36(24)]
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
		
		
		EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
		byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
		Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))
		
		return new Ieee1609Dot2Data(new Ieee1609Dot2Content(new SignedData(HashAlgorithm.sha256, tbsData, signer, signature)))
	}
	


}
