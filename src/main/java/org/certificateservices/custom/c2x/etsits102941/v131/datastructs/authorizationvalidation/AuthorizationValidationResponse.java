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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;

import java.io.IOException;

/**
 * Class representing AuthorizationValidationResponse defined in ETSI TS 102 941 Authorization Validation Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorizationValidationResponse extends COERSequence {

	private static final int OCTETSTRING_SIZE = 16;

	private static final long serialVersionUID = 1L;

	private static final int REQUESTHASH = 0;
	private static final int RESPONSECODE = 1;
	private static final int CONFIRMEDSUBJECTATTRIBUTES = 2;

	/**
	 * Constructor used when decoding
	 */
	public AuthorizationValidationResponse(){
		super(true,3);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public AuthorizationValidationResponse(byte[] requestHash, AuthorizationValidationResponseCode responseCode,
										   CertificateSubjectAttributes confirmedSubjectAttributes) throws IOException{
		super(true,3);
		init();
		if(responseCode == null){
			throw new IOException("Illegal argument: responseCode cannot be null for AuthorizationValidationResponse");
		}
		if(confirmedSubjectAttributes != null && confirmedSubjectAttributes.getCertIssuePermissions() != null){
			throw new IOException("Invalid confirmedSubjectAttributes in AuthorizationValidationResponse, certIssuePermissions cannot be set.");
		}

		set(REQUESTHASH, new COEROctetStream(requestHash, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
        set(RESPONSECODE, new COEREnumeration(responseCode));
        set(CONFIRMEDSUBJECTATTRIBUTES, confirmedSubjectAttributes);
	}


	/**
	 *
	 * @return the 16 byte requestHash value
	 */
	public byte[] getRequestHash(){
		return ((COEROctetStream) get(REQUESTHASH)).getData();
	}

    /**
     *
     * @return responseCode value
     */
    public AuthorizationValidationResponseCode getResponseCode(){
		return (AuthorizationValidationResponseCode) ((COEREnumeration) get(RESPONSECODE)).getValue();
    }

    /**
     *
     * @return confirmedSubjectAttributes value
     */
    public CertificateSubjectAttributes getConfirmedSubjectAttributes(){
        return (CertificateSubjectAttributes) get(CONFIRMEDSUBJECTATTRIBUTES);
    }

	private void init(){
		addField(REQUESTHASH, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
        addField(RESPONSECODE, false, new COEREnumeration(AuthorizationValidationResponseCode.class), null);
        addField(CONFIRMEDSUBJECTATTRIBUTES, true, new CertificateSubjectAttributes(), null);
	}

    @Override
    public String toString() {
    	String attrString = "NONE";
    	if(getConfirmedSubjectAttributes() != null){
			attrString = getConfirmedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ");
		}
        return "AuthorizationValidationResponse [\n" +
                        "  requestHash=" + new String(Hex.encode(getRequestHash())) + "\n" +
                        "  responseCode=" + getResponseCode()  + "\n" +
                        "  confirmedSubjectAttributes=" + attrString + "\n" +
                        "]";
    }

}
