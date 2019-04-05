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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment

import spock.lang.Specification
import spock.lang.Unroll

import static EnrollmentResponseCode.*

/**
 * Unit tests for EnrollmentResponseCode.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EnrollmentResponseCodeSpec extends Specification {

    @Unroll
    def "Verify that #value have the following ordinal #ordinal"(){
        expect:
        value.ordinal() == ordinal

        where:
        ordinal | value
        0       | ok
        1       | cantparse
        2       | badcontenttype
        3       | imnottherecipient
        4       | unknownencryptionalgorithm
        5       | decryptionfailed
        6       | unknownits
        7       | invalidsignature
        8       | invalidencryptionkey
        9       | baditsstatus
        10      | incompleterequest
        11      | deniedpermissions
        12      | invalidkeys
        13      | deniedrequest
    }


}
