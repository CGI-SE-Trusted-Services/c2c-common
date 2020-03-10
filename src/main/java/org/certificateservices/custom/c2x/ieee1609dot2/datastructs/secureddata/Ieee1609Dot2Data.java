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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

/**
 * This data type is used to contain the other data types in this clause. The fields in the Ieee1609Dot2Data have the following meanings.
 * <li>protocolVersion contains the current version of the protocol. The version specified in this document is version 3, represented by the integer 3. 
 * There are no major or minor version numbers.
 * <li>content contains the content in the form of an Ieee1609Dot2Content.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Ieee1609Dot2Data extends COERSequence {
	
	public static final int DEFAULT_VERSION = 3;

	private static final long serialVersionUID = 1L;
	
	private static final int PROTOCOLVERSION = 0;
	private static final int CONTENT = 1;

	/**
	 * Constructor used when decoding
	 */
	public Ieee1609Dot2Data(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding using default protocol version
	 */
	public Ieee1609Dot2Data(Ieee1609Dot2Content content) throws IOException{
		this(DEFAULT_VERSION, content);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Ieee1609Dot2Data(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
		super(false,2);
		init();
		set(PROTOCOLVERSION, new Uint8(protocolVersion));
		set(CONTENT, content);
	
	}
	
	/**
	 * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
	 * @param encodedData byte array encoding of the Ieee1609Dot2Data.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public Ieee1609Dot2Data(byte[] encodedData) throws IOException{
		super(false,2);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 * 
	 * @return protocolVersion
	 */
	public int getProtocolVersion(){
		return (int) ((Uint8) get(PROTOCOLVERSION)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return content
	 */
	public Ieee1609Dot2Content getContent(){
		return (Ieee1609Dot2Content) get(CONTENT);
	}
	
	/**
	 * Encodes the Ieee1609Dot2Data as a byte array.
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
	
	private void init(){
		addField(PROTOCOLVERSION, false, new Uint8(), null);
		addField(CONTENT, false, new Ieee1609Dot2Content(), null);
	}
	
	@Override
	public String toString() {
		return "Ieee1609Dot2Data [\n" +
	    "  protocolVersion=" + getProtocolVersion() + ",\n" +
	    "  content=" + getContent().toString().replace("Ieee1609Dot2Content ", "").replaceAll("\n", "\n  ")  + 
	    "\n]";
	}
	
}
