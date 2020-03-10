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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;

import java.io.*;

/**
 * Class representing EtsiTs102941Data defined in ETSI TS 102 941 Messages CA Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EtsiTs102941Data extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int VERSION = 0;
	private static final int CONTENT = 1;

	/**
	 * Constructor used when decoding
	 */
	public EtsiTs102941Data(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public EtsiTs102941Data(EtsiTs102941DataContent content) throws IOException{
		super(false,2);
		init();

		set(VERSION, new COERInteger(1,0,1));
		set(CONTENT, content);
	}

	/**
	 * Constructor decoding a EtsiTs102941Data from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedCertificate.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public EtsiTs102941Data(byte[] encodedData) throws IOException{
		super(false,2);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	private void init(){
		addField(VERSION, false, new COERInteger(0,1), null);
		addField(CONTENT, false, new EtsiTs102941DataContent(), null);
		
	}
	
	/**
	 * @return the version, required
	 */
	public COERInteger getVersion() {
		return (COERInteger) get(VERSION);
	}

	/**
	 * @return the content, required
	 */
	public EtsiTs102941DataContent getContent() {
		return (EtsiTs102941DataContent) get(CONTENT);
	}

	/**
	 * Encodes the EtsiTs102941Data as a byte array.
	 *
	 * @return return encoded version of the Ieee1609Dot2Data as a byte[]
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
		"EtsiTs102941Data [\n" +
	    "  version=" + getVersion().getValueAsLong() + "\n" +
	    "  content=" + getContent().toString().replaceAll("EtsiTs102941DataContent ", "").replaceAll("\n","\n  ") + "\n" +
	    "]";
	}
}
