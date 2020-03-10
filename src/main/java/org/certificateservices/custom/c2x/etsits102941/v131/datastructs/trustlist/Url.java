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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist;

import org.certificateservices.custom.c2x.asn1.coer.COERIA5String;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * Class representing Url defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Url extends COERIA5String {

    /**
     * Constructor used when decoding a string from Url and no lower or upper bounds are known.
     */
    public Url() {
    }

    /**
     * Constructor used when encoding a string to url encoded format when the lower and upper bound of the string is known.
     *
     */
    public Url(String url, Integer lowerBound, Integer upperBound) throws IOException {
        super(url, lowerBound, upperBound);
    }

    /**
     * Constructor used when encoding a string to url format when no size bounds of the string is known.
     *
     * @param url
     */
    public Url(String url) throws IOException {
        super(url);
    }

    /**
     * Constructor used for decoding when the lower and upper bounds of the string size is known.
     *
     * @param lowerBound
     * @param upperBound
     */
    public Url(Integer lowerBound, Integer upperBound) {
        super(lowerBound, upperBound);
    }

    /**
     *
     * @return the url string
     */
    public String getUrl(){
        return super.getAI5String();
    }

    /**
     * Returns a displayable format of the content of the COEREncodable
     * <p>
     * <b>Important: this method does not return the URL String data, use getUrl() instead.</b>
     */
    @Override
    public String toString() {
        return "URL [" + getUrl() + "]";
    }
}
