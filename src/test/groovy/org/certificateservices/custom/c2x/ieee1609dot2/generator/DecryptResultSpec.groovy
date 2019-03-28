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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import org.bouncycastle.util.encoders.Hex
import spock.lang.Specification

import javax.crypto.SecretKey

/**
 * Unit tests for DecryptResult.
 *
 *  @author Philip Vendil, p.vendil@cgi.com
 */
class DecryptResultSpec extends Specification {

    SecretKey secretKey = Mock(SecretKey)
    byte[] data = Hex.decode("313233")

    def "Verify constructor and getters"(){
        when:
        DecryptResult dr = new DecryptResult(secretKey,data)
        then:
        dr.secretKey == secretKey
        dr.data == data
    }

    def "Verify toString()"(){
        expect:
        new DecryptResult(secretKey,data).toString() == """DecryptAndVerifyResult [
  secretKey=EXISTS,
  data=313233
]"""
        new DecryptResult(null,data).toString() == """DecryptAndVerifyResult [
  secretKey=NONE,
  data=313233
]"""
    }
}
