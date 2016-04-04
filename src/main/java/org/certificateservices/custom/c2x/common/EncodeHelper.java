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
	
	public static void writeFixedFieldSizeKey(int fieldSize, OutputStream out, BigInteger keyValue) throws UnsupportedOperationException, IOException{
		byte[] valueByteArray = keyValue.toByteArray();
		if(valueByteArray.length < fieldSize){
			out.write(new byte[fieldSize - valueByteArray.length]);
		}
		if(valueByteArray.length > fieldSize){
		  out.write(valueByteArray, valueByteArray.length-fieldSize, fieldSize);	
		}else{
		  out.write(valueByteArray);
		}
	}
	
	
	
	public static BigInteger readFixedFieldSizeKey(int fieldSize,  InputStream in) throws UnsupportedOperationException, IOException{
		byte[] data = new byte[fieldSize +1];
		in.read(data,1,fieldSize);		
		return new BigInteger(data);
	}
	
	/**
	 * Help Method to create a displayable string a list of object and replace a substring if necessary.
	 * 
	 * @param list the list to build a displayable string of.
	 * @param removePart substring to remove, use null when retaining all.
	 * @return a displayable string
	 */
	public static String listToString(List<?> list, String removePart){
		return listToString(list, removePart, false, 0);
	}
		
	/**
	 * Help Method to create a displayable string a list of object and replace a substring if necessary.
	 * 
	 * @param list the list to build a displayable string of.
	 * @param removePart substring to remove, use null when retaining all.
	 * @param insertNewline if a new line should be added after each entry
	 * @param indentLevel the number of spaces to a insert before the entry. (only used if insertNewline is true)
	 * @return a displayable string
	 */
	public static String listToString(List<?> list, String removePart, boolean insertNewline, int indentLevel){
		return listToString(list, removePart, insertNewline, indentLevel, null);
	}
	
	/**
	 * Help Method to create a displayable string a list of object and replace a substring if necessary.
	 * 
	 * @param list the list to build a displayable string of.
	 * @param removePart substring to remove, use null when retaining all.
	 * @param insertNewline if a new line should be added after each entry
	 * @param indentLevel the number of spaces to a insert before the entry. (only used if insertNewline is true)
	 * @param toStringCallback callback to handle each object in list toString method separately. null for standard toString behaviour.
	 * @return a displayable string
	 */
	public static String listToString(List<?> list, String removePart, boolean insertNewline, int indentLevel, ToStringCallback toStringCallback){
		String string = "";
		
		String indentString = "";
		for(int i=0;i< indentLevel; i++){
			indentString += " ";
		}
		if(insertNewline && list.size() > 0){
			string += "\n";
		}
		
		for(int i=0; i < list.size() -1; i++){
			Object o = list.get(i);
			String objectString = (toStringCallback == null ? o.toString() : toStringCallback.toString(o));
			if(removePart != null){
				objectString = objectString.replace(removePart, "");
			}
			
			if(insertNewline){
				string += objectString + ",\n";
			}else{
				string += objectString + ", ";	
			}
		}
		if(list.size() > 0){
			Object o = list.get(list.size()-1);
			String objectString = (toStringCallback == null ? o.toString() : toStringCallback.toString(o));
			if(removePart != null){
				objectString = objectString.replace(removePart, "");
			}
			string += objectString;
		}
		
		return string.replace("\n", "\n" + indentString);
	}
	
	/**
	 * Special interface to handle special cases of toString handling of separate objects in a list.
	 *
	 */
	public interface ToStringCallback{
		String toString(Object o);
	}

}
