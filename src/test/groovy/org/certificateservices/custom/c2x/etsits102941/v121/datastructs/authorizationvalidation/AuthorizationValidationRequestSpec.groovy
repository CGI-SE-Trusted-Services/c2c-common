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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.InnerAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.SharedAtRequest
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.EcSignature

/**
 * Unit tests for AuthorizationValidationRequest
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class AuthorizationValidationRequestSpec extends BaseStructSpec {

    SharedAtRequest sharedAtRequest = InnerAtRequestSpec.genSharedAtRequest()
    EcSignature ecSignature = InnerAtRequestSpec.genEcSignature()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        AuthorizationValidationRequest r = new AuthorizationValidationRequest(sharedAtRequest, ecSignature)
        then:
        serializeToHex(r) == "0000001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        when:
        AuthorizationValidationRequest r2 = deserializeFromHex(new AuthorizationValidationRequest(), "0000001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314")
        then:
        r2.getSharedAtRequest() == sharedAtRequest
        r2.getEcSignature() == ecSignature
    }

    def "Verify toString()"(){
        expect:
        new AuthorizationValidationRequest(sharedAtRequest, ecSignature).toString() == """AuthorizationValidationRequest [
  sharedAtRequest=[
    eaId=[0011223344556677]
    keyTag=00112233445566778899001122334455
    certificateFormat=COERInteger [value=1]
    requestedSubjectAttributes=[
      id=[name=[SomeCertId]]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=NONE
    ]
  ]
  ecSignature=[encryptedEcSignature=EtsiTs103097Data [
      protocolVersion=2,
      content=[
        encryptedData=[
          recipients=[[certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]],
          ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
        ]
      ]
    ]
  ]
]"""
    }
}
