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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8;

import java.io.IOException;

/**
 * Class representing DcEntry defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class DcEntry extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int URL = 0;
	private static final int CERT = 1;

	/**
	 * Constructor used when decoding
	 */
	public DcEntry(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public DcEntry(Url url, SequenceOfHashedId8 cert) throws IOException {
		super(false,2);
		init();

		set(URL, url);
        set(CERT, cert);
	}


	/**
	 *
	 * @return the url value
	 */
	public Url getUrl(){
		return (Url) get(URL);
	}

    /**
     *
     * @return cert value
     */
    public SequenceOfHashedId8 getCert(){
		return (SequenceOfHashedId8) get(CERT);
    }

	private void init(){
		addField(URL, false, new Url(), null);
        addField(CERT, false, new SequenceOfHashedId8(), null);
	}

    @Override
    public String toString() {
        return "DcEntry [\n" +
                        "  url=" + getUrl().getUrl() + "\n" +
                        "  cert=" + getCert() + "\n" +
                        "]";
    }

}
