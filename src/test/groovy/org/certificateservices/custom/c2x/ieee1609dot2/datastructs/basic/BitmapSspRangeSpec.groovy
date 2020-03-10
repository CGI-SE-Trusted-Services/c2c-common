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
import org.certificateservices.custom.c2x.common.BaseStructSpec

/**
 * Test for BitmapSspRange
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class BitmapSspRangeSpec extends BaseStructSpec {

    byte[] sspValue = Hex.decode("010203040506070809")
    byte[] sspBitMask = Hex.decode("111203040506071819")

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        BitmapSspRange r1 = new BitmapSspRange(sspValue,sspBitMask)
        then:
        serializeToHex(r1) == "0901020304050607080909111203040506071819"
        when:
        BitmapSspRange r2 = deserializeFromHex(new BitmapSspRange(), "0901020304050607080909111203040506071819")
        then:
        r2.getSspValue() == sspValue
        r2.getSspBitMask() == sspBitMask

    }

    def "Verify that all fields must be set or IOException is thrown when encoding"(){
        when:
        serializeToHex(new BitmapSspRange(sspValue, null))
        then:
        thrown IOException
        when:
        serializeToHex(new BitmapSspRange(null, sspBitMask))
        then:
        thrown IOException
        when:
        serializeToHex(new BitmapSspRange(new byte[0], sspBitMask))
        then:
        thrown IOException
        when:
        serializeToHex(new BitmapSspRange(sspValue,new byte[0]))
        then:
        thrown IOException
        when:
        serializeToHex(new BitmapSspRange(new byte[33], sspBitMask))
        then:
        thrown IOException
        when:
        serializeToHex(new BitmapSspRange(sspValue,new byte[33]))
        then:
        thrown IOException
    }

    def "Verify toString"(){
        expect:
        new BitmapSspRange(sspValue,sspBitMask).toString() == "BitmapSspRange [sspValue=010203040506070809, sspBitmask=111203040506071819]"
    }


}
