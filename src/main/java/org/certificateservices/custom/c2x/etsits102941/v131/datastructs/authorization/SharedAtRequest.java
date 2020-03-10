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
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.*;

/**
 * Class representing SharedAtRequest defined in ETSI TS 102 941 Authorization Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SharedAtRequest extends COERSequence {

	private static final int OCTETSTRING_SIZE = 16;

	private static final long serialVersionUID = 1L;

	private static final int EAID = 0;
	private static final int KEYTAG = 1;
	private static final int CERTIFICATEFORMAT = 2;
	private static final int REQUESTEDSUBJECTATTRIBUTES = 3;

	/**
	 * Constructor used when decoding
	 */
	public SharedAtRequest(){
		super(true,4);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public SharedAtRequest(HashedId8 eaId, byte[] keyTag, CertificateFormat certificateFormat,
						   CertificateSubjectAttributes requestedSubjectAttributes) throws IOException{
		super(true,4);
		init();

		if(requestedSubjectAttributes != null && requestedSubjectAttributes.getCertIssuePermissions() != null){
            throw new IOException("Invalid requestedSubjectAttributes in SharedAtRequest, certIssuePermissions cannot be set.");
        }

		set(EAID, eaId);
		set(KEYTAG, new COEROctetStream(keyTag, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
        set(CERTIFICATEFORMAT, certificateFormat);
        set(REQUESTEDSUBJECTATTRIBUTES, requestedSubjectAttributes);
	}

	/**
	 * Constructor decoding a SharedAtRequest from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedCertificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public SharedAtRequest(byte[] encodedData) throws IOException{
		super(true,4);
		init();

		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 *
	 * @return eaId value
	 */
	public HashedId8 getEaId(){
		return (HashedId8) get(EAID);
	}

    /**
     *
     * @return keyTag value
     */
    public byte[] getKeyTag(){
        return ((COEROctetStream) get(KEYTAG)).getData();
    }

    /**
     *
     * @return certificateFormat value
     */
    public CertificateFormat getCertificateFormat(){
        return (CertificateFormat) get(CERTIFICATEFORMAT);
    }

    /**
     *
     * @return requestedSubjectAttributes value
     */
    public CertificateSubjectAttributes getRequestedSubjectAttributes(){
        return (CertificateSubjectAttributes) get(REQUESTEDSUBJECTATTRIBUTES);
    }


	private void init(){
		addField(EAID, false, new HashedId8(), null);
		addField(KEYTAG, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
        addField(CERTIFICATEFORMAT, false, new CertificateFormat(), null);
        addField(REQUESTEDSUBJECTATTRIBUTES, false, new CertificateSubjectAttributes(), null);
	}

	/**
	 * Encodes the SharedAtRequest as a byte array.
	 *
	 * @return return encoded version of the SharedAtRequest as a byte[]
	 * @throws IOException if encoding problems of the data occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();
	}


	@Override
	public String toString() {
		return
                "SharedAtRequest [\n" +
                "  eaId=" + getEaId().toString().replaceAll("HashedId8 ", "") + "\n" +
                "  keyTag=" + new String(Hex.encode(getKeyTag())) + "\n" +
                "  certificateFormat=" + getCertificateFormat() + "\n" +
                "  requestedSubjectAttributes=" + getRequestedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ") + "\n" +
                "]";
	}

}
