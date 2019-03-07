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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.bouncycastle.util.encoders.Hex
import spock.lang.Specification

/**
 * Unit tests for BitmapSsp
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class BitmapSspSpec extends Specification {

    def "Verify that empty data is allowed"(){
        expect:
        new BitmapSsp(new byte[0]).getData() == new byte[0]
    }

    def "Verify that IllegalArgumentException is thrown for data larger that max size"(){
        when:
        new BitmapSsp(new byte[32])
        then:
        def e = thrown IllegalArgumentException
        e.message == "Error given data to octet stream is larger than maximal value of 31"
    }

    def "Verify that data is stored correctly"(){
        expect:
        Hex.toHexString(new BitmapSsp(Hex.decode("01020304050607080910010203040506070809100102030405060708091001")).getData()) == "01020304050607080910010203040506070809100102030405060708091001"
    }

    def "Verify toString()"(){
        expect:
        new BitmapSsp(Hex.decode("01020304050607080910010203040506070809100102030405060708091001")).toString() == "BitmapSsp [01020304050607080910010203040506070809100102030405060708091001]"
    }

}
