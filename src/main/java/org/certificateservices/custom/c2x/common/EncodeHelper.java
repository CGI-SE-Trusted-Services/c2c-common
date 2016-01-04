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
package org.certificateservices.custom.c2x.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;

/**
 * Helper class for encoding and decoding ITS data structures.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncodeHelper {
	
	/**
	 * Help method that serializes variable sized vector to the supplied data output stream.
	 * 
	 * @param out the data output stream to encode the variable sized vector to,
	 * 
	 * @param variableSizeVector the variable sized vector (a list of StructSerializer)
	 * @throws IOException if serialization failed.
	 */
	public static void encodeVariableSizeVector(DataOutputStream out, List<? extends Encodable> variableSizeVector) throws IOException{
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	DataOutputStream dos = new DataOutputStream(baos);    		 
		for(Encodable next: variableSizeVector){
			next.encode(dos);
		}
		byte[] data = baos.toByteArray();
		IntX size = new IntX(data.length);
		size.encode(out);
		out.write(data);
	}

	/**
	 * Help method that serializes variable sized vector to the supplied data output stream.
	 * 
	 * @param in the data input stream to decode the variable sized vector from.
	 * 
	 * @param c class of the objects contained in data stream, the class must implement a StructSerializer
	 * @throws IOException if serialization failed.
	 */
	public static List<?> decodeVariableSizeVector(DataInputStream in, Class<?> c) throws IOException{
		ArrayList<Encodable> retval = new ArrayList<Encodable>();
    
		IntX size = new IntX();
		size.decode(in);
		byte[] data = new byte[size.getValue().intValue()];
		in.read(data);
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
		try{
			while(dis.available() > 0){
				Encodable ss = (Encodable) c.newInstance();
				ss.decode(dis);
				retval.add(ss);    		
			}
		}catch(IllegalAccessException e){
			throw new IOException("IllegalAccessException: " + e.getMessage(),e);
		} catch (InstantiationException e) {
			throw new IOException("InstantiationException: " + e.getMessage(),e);
		}
    	
    	return retval;
	}
	
	public static void writeFixedFieldSizeKey(PublicKeyAlgorithm publicKeyAlgorithm, OutputStream out, BigInteger keyValue) throws UnsupportedOperationException, IOException{
		byte[] valueByteArray = keyValue.toByteArray();
		if(valueByteArray.length < publicKeyAlgorithm.getFieldSize()){
			out.write(new byte[publicKeyAlgorithm.getFieldSize() - valueByteArray.length]);
		}
		if(valueByteArray.length > publicKeyAlgorithm.getFieldSize()){
		  out.write(valueByteArray, valueByteArray.length-publicKeyAlgorithm.getFieldSize(), publicKeyAlgorithm.getFieldSize());	
		}else{
		  out.write(valueByteArray);
		}
	}
	
	public static BigInteger readFixedFieldSizeKey(PublicKeyAlgorithm publicKeyAlgorithm,  InputStream in) throws UnsupportedOperationException, IOException{
		byte[] data = new byte[publicKeyAlgorithm.getFieldSize() +1];
		in.read(data,1,publicKeyAlgorithm.getFieldSize());		
		return new BigInteger(data);
	}
	
	

}
