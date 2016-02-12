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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.ToBeSignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SignedData
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SignedDataSpec extends BaseStructSpec {


	HashAlgorithm ha = HashAlgorithm.sha256
	SignedDataPayload sdp = new SignedDataPayload(null, new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")))
	HeaderInfo hi = new HeaderInfo(new Psid(100), null, null, null, null, null, null)
	ToBeSignedData tbs = new ToBeSignedData(sdp,hi)
	
	HashedId8 h = new HashedId8(Hex.decode("0102030405060708"))
	SignerIdentifier signer = new SignerIdentifier(h)
	
	
	EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
	byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
	Signature signature = new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))
	

	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		SignedData sd = new SignedData(ha,tbs,signer,signature)
		then:
		!sd.hasExtension
		serializeToHex(sd) == "00208001020304050607080910111213141516171819202122232425262728293031320001648001020304050607088080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		SignedData sd2 = deserializeFromHex(new SignedData(), "00208001020304050607080910111213141516171819202122232425262728293031320001648001020304050607088080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		!sd2.hasExtension
		sd2.getHashAlgorithm() == ha
		sd2.getTbsData() == tbs
		sd2.getSigner() == signer
		sd2.getSignature() == signature
		
		
	}
	
	def "Verify that IllegalArgumentException is thrown if both data and exthash is null"(){
		when:
		new SignedData(null,tbs,signer,signature)
		then:
		thrown IllegalArgumentException
		when:
		new SignedData(ha,null,signer,signature)
		then:
		thrown IllegalArgumentException
		when:
		new SignedData(ha,tbs,null,signature)
		then:
		thrown IllegalArgumentException
		when:
		new SignedData(ha,tbs,signer,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new SignedData(ha,tbs,signer,signature).toString() == """SignedData [
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
]"""
	}
	

}
