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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;

import java.io.IOException;

/**
 * Class representing InnerAtRequest defined in ETSI TS 102 941 Authorization Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class InnerAtRequest extends COERSequence {

	private static final int OCTETSTRING_SIZE = 32;

	private static final long serialVersionUID = 1L;

	private static final int PUBLICKEYS = 0;
	private static final int HMACKEY = 1;
	private static final int SHAREDATREQUEST = 2;
	private static final int ECSIGNATURE = 3;

	/**
	 * Constructor used when decoding
	 */
	public InnerAtRequest(){
		super(true,4);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public InnerAtRequest(PublicKeys publicKeys, byte[] hmacKey, SharedAtRequest sharedAtRequest, EcSignature ecSignature)
	throws IOException {
		super(true,4);
		init();
		set(PUBLICKEYS, publicKeys);
		set(HMACKEY, new COEROctetStream(hmacKey, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
        set(SHAREDATREQUEST, sharedAtRequest);
        set(ECSIGNATURE, ecSignature);
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
	 * @return the 32 byte hmacKey value
	 */
	public byte[] getHmacKey(){
		return ((COEROctetStream) get(HMACKEY)).getData();
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
		addField(PUBLICKEYS, false, new PublicKeys(), null);
		addField(HMACKEY, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
        addField(SHAREDATREQUEST, false, new SharedAtRequest(), null);
        addField(ECSIGNATURE, false, new EcSignature(), null);
	}

    @Override
    public String toString() {
        return
                "InnerAtRequest [\n" +
                        "  publicKeys=" + getPublicKeys().toString().replaceAll("PublicKeys ", "") + "\n" +
                        "  hmacKey=" + new String(Hex.encode(getHmacKey())) + "\n" +
                        "  sharedAtRequest=" + getSharedAtRequest().toString().replaceAll("SharedAtRequest ","").replaceAll("\n","\n  ")  + "\n" +
                        "  ecSignature=" + getEcSignature().toString().replaceAll("EcSignature ","").replaceAll("\n","\n  ") + "\n" +
                        "]";
    }

}
