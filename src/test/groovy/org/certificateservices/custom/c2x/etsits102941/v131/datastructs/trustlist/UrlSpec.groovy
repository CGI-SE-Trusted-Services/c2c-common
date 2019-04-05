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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist

import spock.lang.Specification

/**
 * Unit test for Url
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class UrlSpec extends Specification {

    def "Verify that constructor and getter"(){
        expect:
        new Url(4,5).getLowerBound() == 4
        new Url(4,5).getUpperBound() == 5
        new Url("http://test.com").getUrl() == "http://test.com"
        new Url("a",1,5).getLowerBound() == 1
        new Url("a",1,5).getUpperBound() == 5
        new Url("ab",1,5).getUrl() == "ab"
    }


    def "Verify toString"(){
        expect:
        new Url("http://test.com").toString() == "URL [http://test.com]"
    }
}
