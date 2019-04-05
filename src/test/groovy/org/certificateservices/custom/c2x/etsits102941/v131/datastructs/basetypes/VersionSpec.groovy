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

import spock.lang.Specification
import spock.lang.Unroll

/**
 * Unit tests for Version
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class VersionSpec extends Specification {

    @Unroll
    def "Verify that correct value #expectedInt is set for #name"(){
        expect:
        value.valueAsLong == expectedInt
        value.minValue == null
        value.maxValue == null
        where:
        name            | value               | expectedInt
        "v1"            | Version.V1          | 1
    }
}
