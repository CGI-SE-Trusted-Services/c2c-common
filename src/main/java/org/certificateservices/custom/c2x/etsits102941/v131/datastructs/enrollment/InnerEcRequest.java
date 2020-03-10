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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERIA5String;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;

import java.io.*;

/**
 * Class representing InnerAtRequest defined in ETSI TS 102 941 Enrollment Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class InnerEcRequest extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int ITSID = 0;
	private static final int CERTIFICATEFORMAT = 1;
	private static final int PUBLICKEYS = 2;
	private static final int REQUESTEDSUBJECTATTRIBUTES = 3;

	/**
	 * Constructor used when decoding
	 */
	public InnerEcRequest(){
		super(true,4);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public InnerEcRequest(byte[] itsId, CertificateFormat certificateFormat, PublicKeys publicKeys,
						  CertificateSubjectAttributes requestedSubjectAttributes)
			throws IOException{
		super(true,4);
		init();

		if(requestedSubjectAttributes != null && requestedSubjectAttributes.getCertIssuePermissions() != null){
			throw new IOException("Invalid requestedSubjectAttributes in InnerEcRequest, certIssuePermissions cannot be set.");
		}

		set(ITSID, new COEROctetStream(itsId));
		set(CERTIFICATEFORMAT, certificateFormat);
		set(PUBLICKEYS, publicKeys);
		set(REQUESTEDSUBJECTATTRIBUTES, requestedSubjectAttributes);
	}

	/**
	 * Constructor decoding a InnerEcRequest from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedCertificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public InnerEcRequest(byte[] encodedData) throws IOException{
		super(true,4);
		init();

		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 *
	 * @return itsId value
	 */
	public byte[] getItsId(){
		return ((COEROctetStream) get(ITSID)).getData();
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

	/**
	 * Encodes the InnerEcRequest as a byte array.
	 *
	 * @return return encoded version of the InnerEcRequest as a byte[]
	 * @throws IOException if encoding problems of the data occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();
	}

	private void init(){
		addField(ITSID, false, new COERIA5String(), null);
		addField(CERTIFICATEFORMAT, false, new CertificateFormat(), null);
		addField(PUBLICKEYS, false, new PublicKeys(), null);
        addField(REQUESTEDSUBJECTATTRIBUTES, false, new CertificateSubjectAttributes(), null);
	}

    @Override
    public String toString() {
        return
                "InnerEcRequest [\n" +
						"  itsId=" + Hex.toHexString(getItsId()) + "\n" +
						"  certificateFormat=" + getCertificateFormat() + "\n" +
                        "  publicKeys=" + getPublicKeys().toString().replaceAll("PublicKeys ", "") + "\n" +
                        "  requestedSubjectAttributes=" + getRequestedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ")  + "\n" +
                        "]";
    }

}
