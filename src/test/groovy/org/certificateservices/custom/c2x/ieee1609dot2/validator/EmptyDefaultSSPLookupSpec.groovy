/************************************************************************
 *                                                                       *
 *  Certificate Service - Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.validator

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import spock.lang.Specification

/**
 * Unit tests for EmptyDefaultSSPLookup.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EmptyDefaultSSPLookupSpec extends Specification {

    EmptyDefaultSSPLookup lookup = new EmptyDefaultSSPLookup()

    def "Verify that getDefaultSSP always returns null"(){
        expect:
        lookup.getDefaultSSP(null) == null
        lookup.getDefaultSSP(new Psid(123)) == null
    }

    def "Verify that getDefaultSSPRange always returns null"(){
        expect:
        lookup.getDefaultSSPRange(null) == null
        lookup.getDefaultSSPRange(new Psid(123)) == null
    }
}
