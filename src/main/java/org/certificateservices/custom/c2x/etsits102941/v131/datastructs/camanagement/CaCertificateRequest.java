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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;

import java.io.IOException;

/**
 * Class representing CaCertificateRequest defined in ETSI TS 102 941 CA Management Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CaCertificateRequest extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int PUBLICKEYS = 0;
	private static final int REQUESTEDSUBJECTATTRIBUTES = 1;

	/**
	 * Constructor used when decoding
	 */
	public CaCertificateRequest(){
		super(true,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public CaCertificateRequest(PublicKeys publicKeys,
								CertificateSubjectAttributes requestedSubjectAttributes) throws IOException {
		super(true,2);
		init();
		set(PUBLICKEYS, publicKeys);
		set(REQUESTEDSUBJECTATTRIBUTES, requestedSubjectAttributes);
	}

	/**
	 *
	 * @return publicKeys value
	 */
	public PublicKeys getPublicKeys(){
		return (PublicKeys) get(PUBLICKEYS);
	}

    /**
     *
     * @return requestedSubjectAttributes value
     */
    public CertificateSubjectAttributes getRequestedSubjectAttributes(){
        return (CertificateSubjectAttributes) get(REQUESTEDSUBJECTATTRIBUTES);
    }


	private void init(){
		addField(PUBLICKEYS, false, new PublicKeys(), null);
        addField(REQUESTEDSUBJECTATTRIBUTES, false, new CertificateSubjectAttributes(), null);
	}

    @Override
    public String toString() {
        return
                "CaCertificateRequest [\n" +
                        "  publicKeys=" + getPublicKeys().toString().replaceAll("PublicKeys ", "") + "\n" +
                        "  requestedSubjectAttributes=" + getRequestedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ")  + "\n" +
                        "]";
    }

}
