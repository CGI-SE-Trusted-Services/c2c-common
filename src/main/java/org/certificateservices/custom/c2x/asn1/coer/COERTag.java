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
package org.certificateservices.custom.c2x.asn1.coer;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * COER tags are encoded only as part of the encoding of a choice type, where the tag indicates which alternative of the choice type is the chosen alternative.
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 8.7
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERTag implements COEREncodable{

	private static final long serialVersionUID = 1L;
	
	public static int UNIVERSIAL_TAG_CLASS = 0x00;
	public static int APPLICATION_TAG_CLASS = 0x40;
	public static int CONTEXT_SPECIFIC_TAG_CLASS = 0x80;
	public static int PRIVATE_TAG_CLASS = 0xc0;
	
	private static final Map<Integer, String> classNames = new HashMap<Integer, String>();
	static{
		classNames.put(UNIVERSIAL_TAG_CLASS, "UNIVERSIAL_TAG_CLASS");
		classNames.put(APPLICATION_TAG_CLASS, "APPLICATION_TAG_CLASS");
		classNames.put(CONTEXT_SPECIFIC_TAG_CLASS, "CONTEXT_SPECIFIC_TAG_CLASS");
		classNames.put(PRIVATE_TAG_CLASS, "PRIVATE_TAG_CLASS");
	}
	
	private int tagClass;

	private long tagNumber;
	
	/**
	 * Constructor for decoding a COER Tag.
	 */
	public COERTag(){}
	
	/**
	 * Constructor for encoding a COER tag given a class and tag number.
	 */
	public COERTag(int tagClass, long tagNumber) throws IOException{
		this.tagClass = tagClass;
		this.tagNumber = tagNumber;
	}
	
	/**
	 * 
	 * @return the tag class.
	 */
	public int getTagClass() {
		return tagClass;
	}

	/**
	 * 
	 * @return the tag number.
	 */
	public long getTagNumber() {
		return tagNumber;
	}

	/**
	 * 
	 * @return returns the tag data in COER encoding.
	 */
	public byte[] getEncoded(){
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		if (tagNumber < 63) 
		{
			baos.write(tagClass | (byte) tagNumber);
		}
		else
		{
			baos.write(tagClass | 0x3F);
			if (tagNumber < 128)
			{
				baos.write((byte) tagNumber);
			}
			else
			{
				byte[] buffer = new byte[9];
				int index = buffer.length;

				buffer[--index] = (byte)(tagNumber & 0x7F);

				do
				{
					tagNumber >>= 7;
			        buffer[--index] = (byte)(tagNumber & 0x7F | 0x80);
				}
				while (tagNumber > 127);

				baos.write(buffer, index, buffer.length - index);
			}
		}
		
		return baos.toByteArray();
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(getEncoded());
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		
		int firstByte = in.read();
		tagClass = firstByte & 0xc0;
		
		firstByte = firstByte & 0x3F;
		if(firstByte < 63){
			tagNumber = firstByte;
		}else{
			tagNumber=0;
			int nextByte = in.read();
			
			if ((nextByte & 0x7f) == 0) 
			{
				throw new IOException("Invalid tag encoding, tag byte cannot be zero.");
			}
          while ((nextByte >= 0) && ((nextByte & 0x80) != 0))
          {
        	  tagNumber |= (nextByte & 0x7f);
        	  tagNumber <<= 7;
        	  nextByte = in.read();
          }

          if (nextByte < 0)
          {
              throw new EOFException("EOF found inside tag value.");
          }
          
          tagNumber |= (nextByte & 0x7f);
					
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + tagClass;
		result = prime * result + (int) (tagNumber ^ (tagNumber >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		COERTag other = (COERTag) obj;
		if (tagClass != other.tagClass)
			return false;
		if (tagNumber != other.tagNumber)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COERTag [tagClass=" + tagClass + " (" + classNames.get(tagClass) + ") , tagNumber=" + tagNumber
				+ "]";
	}
	
	
	
}
