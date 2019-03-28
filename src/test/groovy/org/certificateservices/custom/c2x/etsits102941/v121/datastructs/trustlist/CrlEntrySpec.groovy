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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec

/**
 * Unit test for CrlEntry
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CrlEntrySpec extends BaseStructSpec {

   byte[] digest = Hex.decode("001122334455667788")

    def "Verify constructor and serialization"(){
        when:
        CrlEntry ce1 = new CrlEntry(digest)
        then:
        serializeToHex(ce1) == "1122334455667788"

        when:
        CrlEntry ce2 = deserializeFromHex(new CrlEntry(),"1122334455667788")
        then:
        ce1 == ce2
    }

    def "Verify toString()"(){
        expect:
        new CrlEntry(digest).toString() == "CrlEntry [1122334455667788]"
    }
}
