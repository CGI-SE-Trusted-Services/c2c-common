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
public class TlmEntry extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int SELFSIGNEDTLMCERTIFICATE = 0;
	private static final int LINKTLMCERTIFICATE = 1;
	private static final int ACCESSPOINT = 2;

	/**
	 * Constructor used when decoding
	 */
	public TlmEntry(){
		super(false,3);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public TlmEntry(EtsiTs103097Certificate selfSignedTLMCertificate,
					EtsiTs103097Certificate linkTLMCertificate, Url accessPoint) throws IOException {
		super(false,3);
		init();

		set(SELFSIGNEDTLMCERTIFICATE, selfSignedTLMCertificate);
        set(LINKTLMCERTIFICATE, linkTLMCertificate);
		set(ACCESSPOINT, accessPoint);
	}

	/**
	 *
	 * @return the selfSignedTLMCertificate value
	 */
	public EtsiTs103097Certificate getSelfSignedTLMCertificate(){
		return (EtsiTs103097Certificate) get(SELFSIGNEDTLMCERTIFICATE);
	}

	/**
	 *
	 * @return the linkTLMCertificate value
	 */
	public EtsiTs103097Certificate getLinkTLMCertificate(){
		return (EtsiTs103097Certificate) get(LINKTLMCERTIFICATE);
	}

	/**
	 *
	 * @return the accessPoint value
	 */
	public Url getAccessPoint(){
		return (Url) get(ACCESSPOINT);
	}

	private void init(){
		addField(SELFSIGNEDTLMCERTIFICATE, false, new EtsiTs103097Certificate(), null);
        addField(LINKTLMCERTIFICATE, true, new EtsiTs103097Certificate(), null);
		addField(ACCESSPOINT, false, new Url(), null);
	}

    @Override
    public String toString() {
		String linkCertString = "NONE";
		if( getLinkTLMCertificate() != null){
			linkCertString =  getLinkTLMCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ");
		}

        return "TlmEntry [\n" +
                        "  selfSignedTLMCertificate=" + getSelfSignedTLMCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ") + "\n" +
                        "  linkTLMCertificate=" + linkCertString + "\n" +
				        "  accessPoint=" + getAccessPoint().getUrl() + "\n" +
                        "]";
    }

}
