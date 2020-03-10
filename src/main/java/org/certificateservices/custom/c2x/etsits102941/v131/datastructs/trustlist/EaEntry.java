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
 * Class representing EaEntry defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EaEntry extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int EACERTIFICATE = 0;
	private static final int AAACCESSPOINT = 1;
	private static final int ITSACCESSPOINT = 2;

	/**
	 * Constructor used when decoding
	 */
	public EaEntry(){
		super(false,3);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public EaEntry(EtsiTs103097Certificate eaCertificate, Url aaAccessPoint, Url itsAccessPoint) throws IOException {
		super(false,3);
		init();

		set(EACERTIFICATE, eaCertificate);
        set(AAACCESSPOINT, aaAccessPoint);
		set(ITSACCESSPOINT, itsAccessPoint);
	}

	/**
	 *
	 * @return the aaCertificate value
	 */
	public EtsiTs103097Certificate getEaCertificate(){
		return (EtsiTs103097Certificate) get(EACERTIFICATE);
	}

	/**
	 *
	 * @return the aaAccessPoint value
	 */
	public Url getAaAccessPoint(){
		return (Url) get(AAACCESSPOINT);
	}

	/**
	 *
	 * @return the itsAccessPoint value
	 */
	public Url getItsAccessPoint(){
		return (Url) get(ITSACCESSPOINT);
	}

	private void init(){
		addField(EACERTIFICATE, false, new EtsiTs103097Certificate(), null);
        addField(AAACCESSPOINT, false, new Url(), null);
		addField(ITSACCESSPOINT, true, new Url(), null);
	}

    @Override
    public String toString() {
		String itsAccessPoint = "NONE";
		if(getItsAccessPoint() != null){
			itsAccessPoint = getItsAccessPoint().getUrl();
		}
        return "EaEntry [\n" +
                        "  eaCertificate=" + getEaCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ") + "\n" +
                        "  aaAccessPoint=" + getAaAccessPoint().getUrl() + "\n" +
				        "  itsAccessPoint=" + itsAccessPoint + "\n" +
                        "]";
    }

}
