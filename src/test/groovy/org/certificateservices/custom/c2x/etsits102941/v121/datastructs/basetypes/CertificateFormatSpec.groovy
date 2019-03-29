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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes

import spock.lang.Specification
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateFormat.*
/**
 * Unit tests for CertificateFormat
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CertificateFormatSpec extends Specification {

    @Unroll
    def "Verify that correct value #expectedInt is set for #name"(){
        expect:
        value.valueAsLong == expectedInt
        value.minValue.toInteger() == 1
        value.maxValue.toInteger() == 255
        where:
        name            | value               | expectedInt
        "ts103097v131"  | TS103097C131        | 1
    }
}
