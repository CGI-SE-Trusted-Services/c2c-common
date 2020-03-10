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
 * Class representing RootCaEntry defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RootCaEntry extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int SELFSIGNEDROOTCA = 0;
	private static final int LINKROOTCACERTIFICATE = 1;

	/**
	 * Constructor used when decoding
	 */
	public RootCaEntry(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public RootCaEntry(EtsiTs103097Certificate selfsignedRootCa,
					   EtsiTs103097Certificate linkRootCaCertificate) throws IOException {
		super(false,2);
		init();

		set(SELFSIGNEDROOTCA, selfsignedRootCa);
        set(LINKROOTCACERTIFICATE, linkRootCaCertificate);
	}

	/**
	 *
	 * @return the selfsignedRootCa value
	 */
	public EtsiTs103097Certificate getSelfsignedRootCa(){
		return (EtsiTs103097Certificate) get(SELFSIGNEDROOTCA);
	}

	/**
	 *
	 * @return the linkRootCaCertificate value
	 */
	public EtsiTs103097Certificate getLinkRootCaCertificate(){
		return (EtsiTs103097Certificate) get(LINKROOTCACERTIFICATE);
	}

	private void init(){
		addField(SELFSIGNEDROOTCA, false, new EtsiTs103097Certificate(), null);
        addField(LINKROOTCACERTIFICATE, true, new EtsiTs103097Certificate(), null);
	}

    @Override
    public String toString() {
		String linkCertString = "NONE";
		if( getLinkRootCaCertificate() != null){
			linkCertString =  getLinkRootCaCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ");
		}

        return "RootCaEntry [\n" +
                        "  selfsignedRootCa=" + getSelfsignedRootCa().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ") + "\n" +
                        "  linkRootCaCertificate=" + linkCertString + "\n" +
                        "]";
    }

}
