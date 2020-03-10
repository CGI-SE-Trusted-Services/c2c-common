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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.io.IOException;

/**
 * Class representing InnerAtResponse defined in ETSI TS 102 941 Authorization Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class InnerAtResponse extends COERSequence {

	private static final int OCTETSTRING_SIZE = 16;

	private static final long serialVersionUID = 1L;

	private static final int REQUESTHASH = 0;
	private static final int RESPONSECODE = 1;
	private static final int CERTIFICATE = 2;


	/**
	 * Constructor used when decoding
	 */
	public InnerAtResponse(){
		super(true,3);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public InnerAtResponse(byte[] requestHash, AuthorizationResponseCode responseCode, EtsiTs103097Certificate certificate) throws IOException {
		super(true,3);
		init();
		if(responseCode == null){
			throw new IOException("Illegal argument: responseCode cannot be null for InnerAtResponse");
		}
		if(responseCode == AuthorizationResponseCode.ok){
			if(certificate == null){
				throw new IOException("Illegal argument: certificate cannot be null if response code is ok.");
			}
		}else{
			if(certificate != null){
				throw new IOException("Illegal argument: certificate must be null if response code is not ok.");
			}
		}
		set(REQUESTHASH, new COEROctetStream(requestHash, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
        set(RESPONSECODE, new COEREnumeration(responseCode));
        set(CERTIFICATE, certificate);
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
    public AuthorizationResponseCode getResponseCode(){
		return (AuthorizationResponseCode) ((COEREnumeration) get(RESPONSECODE)).getValue();
    }

    /**
     *
     * @return ecSignature value
     */
    public EtsiTs103097Certificate getCertificate(){
        return (EtsiTs103097Certificate) get(CERTIFICATE);
    }

	private void init(){
		addField(REQUESTHASH, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
        addField(RESPONSECODE, false, new COEREnumeration(AuthorizationResponseCode.class), null);
        addField(CERTIFICATE, true, new EtsiTs103097Certificate(), null);
	}

    @Override
    public String toString() {
    	String certString = "NONE";
    	if(getCertificate() != null){
			certString = getCertificate().toString().replaceAll("EtsiTs103097Certificate ","").replaceAll("\n","\n  ");
		}
        return "InnerAtResponse [\n" +
                        "  requestHash=" + new String(Hex.encode(getRequestHash())) + "\n" +
                        "  responseCode=" + getResponseCode()  + "\n" +
                        "  certificate=" + certString + "\n" +
                        "]";
    }

}
