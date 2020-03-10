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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;

import java.io.IOException;

/**
 * Class representing AuthorizationValidation defined in ETSI TS 102 941 Authorization Validation Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorizationValidationRequest extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int SHAREDATREQUEST = 0;
	private static final int ECSIGNATURE = 1;

	/**
	 * Constructor used when decoding
	 */
	public AuthorizationValidationRequest(){
		super(true,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public AuthorizationValidationRequest(SharedAtRequest sharedAtRequest, EcSignature ecSignature) throws IOException {
		super(true,2);
		init();
        set(SHAREDATREQUEST, sharedAtRequest);
        set(ECSIGNATURE, ecSignature);
	}

    /**
     *
     * @return sharedAtRequest value
     */
    public SharedAtRequest getSharedAtRequest(){
        return (SharedAtRequest) get(SHAREDATREQUEST);
    }

    /**
     *
     * @return ecSignature value
     */
    public EcSignature getEcSignature(){
        return (EcSignature) get(ECSIGNATURE);
    }

	private void init(){
        addField(SHAREDATREQUEST, false, new SharedAtRequest(), null);
        addField(ECSIGNATURE, false, new EcSignature(), null);
	}

    @Override
    public String toString() {
        return
                "AuthorizationValidationRequest [\n" +
                        "  sharedAtRequest=" + getSharedAtRequest().toString().replaceAll("SharedAtRequest ","").replaceAll("\n","\n  ")  + "\n" +
                        "  ecSignature=" + getEcSignature().toString().replaceAll("EcSignature ","").replaceAll("\n","\n  ") + "\n" +
                        "]";
    }

}
