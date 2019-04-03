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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*

/**
 * Unit tests for PublicKeys
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PublicKeysSpec extends BaseStructSpec {

    EccP256CurvePoint r_256 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
    PublicVerificationKey verificationKey = new PublicVerificationKey(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, r_256)

    EccP256CurvePoint p = new EccP256CurvePoint(new BigInteger(123))
    BasePublicEncryptionKey pubKey = new BasePublicEncryptionKey(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, p)
    PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey)

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        PublicKeys pks1 = new PublicKeys(verificationKey, encryptionKey)
        then:
        serializeToHex(pks1) == "808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b"
        when:
        PublicKeys pks2 = deserializeFromHex(new PublicKeys(), "808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b")
        then:
        pks2.getVerificationKey() == verificationKey
        pks2.getEncryptionKey() == encryptionKey
        when:
        PublicKeys pks3 = new PublicKeys(verificationKey,null)
        then:
        serializeToHex(pks3) == "008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"
        when:
        PublicKeys pks4 = deserializeFromHex(new PublicKeys(), "008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df")
        then:
        pks4.getVerificationKey() == verificationKey
        pks4.getEncryptionKey() == null

    }

    def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
        when:
        new PublicKeys(null,encryptionKey)
        then:
        thrown IllegalArgumentException
    }


    def "Verify toString"(){
        expect:
        new PublicKeys(verificationKey, encryptionKey).toString() == "PublicKeys [verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]"
        new PublicKeys(verificationKey, null).toString() == "PublicKeys [verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=NONE]"
    }
}
