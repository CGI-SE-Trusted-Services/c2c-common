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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;

import java.io.IOException;

/**
 * Class representing CertificateFormat integer constants.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class CertificateFormat  extends COERInteger {

    public static final CertificateFormat TS103097C131 = new CertificateFormat(1);


    /**
     * Constructor when decoding an integer.
     */
    public CertificateFormat() {
        super(1,255);
    }



    /**
     * Constructor used when encoding integer
     *
     * @param value    the integer value.
     */
    public CertificateFormat(long value) throws IllegalArgumentException {
        super(value, 1, 255);
    }
}
