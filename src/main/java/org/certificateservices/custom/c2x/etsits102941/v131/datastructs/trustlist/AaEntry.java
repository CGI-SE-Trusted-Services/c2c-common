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
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.io.IOException;

/**
 * Class representing AaEntry defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AaEntry extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int AACERTIFICATE = 0;
	private static final int ACCESSPOINT = 1;

	/**
	 * Constructor used when decoding
	 */
	public AaEntry(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public AaEntry(EtsiTs103097Certificate aaCertificate, Url accessPoint) throws IOException {
		super(false,2);
		init();

		set(AACERTIFICATE, aaCertificate);
        set(ACCESSPOINT, accessPoint);
	}

	/**
	 *
	 * @return the aaCertificate value
	 */
	public EtsiTs103097Certificate getAaCertificate(){
		return (EtsiTs103097Certificate) get(AACERTIFICATE);
	}

	/**
	 *
	 * @return the accessPoint value
	 */
	public Url getAccessPoint(){
		return (Url) get(ACCESSPOINT);
	}

	private void init(){
		addField(AACERTIFICATE, false, new EtsiTs103097Certificate(), null);
        addField(ACCESSPOINT, false, new Url(), null);
	}

    @Override
    public String toString() {
        return "AaEntry [\n" +
                        "  aaCertificate=" + getAaCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ") + "\n" +
                        "  accessPoint=" + getAccessPoint().getUrl() + "\n" +
                        "]";
    }

}
