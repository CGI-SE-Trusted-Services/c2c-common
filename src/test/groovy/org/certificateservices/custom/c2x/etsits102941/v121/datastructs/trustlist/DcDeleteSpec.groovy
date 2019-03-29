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

import spock.lang.Specification

/**
 * Unit tests for DcDelete
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class DcDeleteSpec extends Specification {

    def "Verify that constructor and getter"(){
        expect:
        new DcDelete(4,5).getLowerBound() == 4
        new DcDelete(4,5).getUpperBound() == 5
        new DcDelete("http://test.com").getUrl() == "http://test.com"
        new DcDelete("a",1,5).getLowerBound() == 1
        new DcDelete("a",1,5).getUpperBound() == 5
        new DcDelete("ab",1,5).getUrl() == "ab"
    }

    def "Verify toString"(){
        expect:
        new DcDelete("http://test.com").toString() == "DcDelete [http://test.com]"
    }
}
