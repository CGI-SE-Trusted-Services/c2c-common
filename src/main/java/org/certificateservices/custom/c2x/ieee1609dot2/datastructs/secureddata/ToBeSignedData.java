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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * This structure contains the data to be hashed when generating or verifying a signature. See 6.3.4 for the specification of the input to the hash.
 * <li>payload contains data that is provided by the entity that invokes the SDS.   
 * <li>headerInfo contains additional data that is inserted by the SDS.
 * <p>
 * <b>ENCODING CONSIDERATIONS:</b>For encoding considerations associated with the headerInfo field, see 6.3.9.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ToBeSignedData extends COERSequence {
	

	private static final long serialVersionUID = 1L;

	private static final int PAYLOAD = 0;
	private static final int HEADERINFO = 1;

	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedData(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor decoding a ToBeSignedData from an encoded byte array.
	 * @param encodedData byte array encoding of the ToBeSignedData.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public ToBeSignedData(byte[] encodedData) throws IOException{
		super(false,2);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 * Constructor used when encoding
	 */
	public ToBeSignedData(SignedDataPayload payload, HeaderInfo headerInfo) throws IOException{
		super(false,2);
		init();
		set(PAYLOAD, payload);
		set(HEADERINFO, headerInfo);
	
	}

	/**
	 * 
	 * @return payload
	 */
	public SignedDataPayload getPayload(){
		return (SignedDataPayload) get(PAYLOAD);
	}
	
	/**
	 * 
	 * @return headerInfo
	 */
	public HeaderInfo getHeaderInfo(){
		return (HeaderInfo) get(HEADERINFO);
	}
	
	/**
	 * Encodes the ToBeSignedData as a byte array.
	 * 
	 * @return return encoded version of the ToBeSignedData as a byte[] 
	 * @throws IOException if encoding problems of the data occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();		
	}
	
	private void init(){
		addField(PAYLOAD, false, new SignedDataPayload(), null);
		addField(HEADERINFO, false, new HeaderInfo(), null);
	}
	
	@Override
	public String toString() {
		return "ToBeSignedData [\n" +
	    "  payload=" + getPayload().toString().replace("SignedDataPayload ", "").replaceAll("\n", "\n  ") + ",\n" +
	    "  headerInfo=" + getHeaderInfo().toString().replace("HeaderInfo ", "").replaceAll("\n", "\n  ")  + 
	    "\n]";
	}
	
}
