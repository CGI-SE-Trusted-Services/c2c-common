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
package org.certificateservices.custom.c2x.its.datastructs.cert;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This structure defines how to encode information about a certificate's subject. It contains the type of information in
 * subject_type and the information itself in the variable-length vector subject_name. The subject_name
 * variable-length vector shall have a maximum length of 32 bytes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SubjectInfo implements Encodable {
	
	static final int MAX_SUBJECT_NAME_LENGTH = 32;
	
	private SubjectType subjectType;
	private byte[] subjectName;
	
	/**
	 * Main constructor for subject info.
	 *  
	 * @param subjectType the type of subject, one of SubjectType enum.
	 * @param subjectName variable-length vector shall have a maximum length of 32 bytes. Can be null of 0 length subject name.
	 */
	public SubjectInfo(SubjectType subjectType, byte[] subjectName){
		this.subjectType = subjectType;
		if(subjectName == null){
			  this.subjectName = new byte[0];	
		}else{
		  if(subjectName.length > MAX_SUBJECT_NAME_LENGTH){
			throw new IllegalArgumentException("Illegal subject name lenght, should be max " + MAX_SUBJECT_NAME_LENGTH + " bytes.");
		  }
		  this.subjectName = subjectName;
		}
	}
	
	/**
	 * Constructor used during serialization
	 */
	public SubjectInfo(){}
	
	/**
	 * 
	 * @return the type of subject, one of SubjectType enum.
	 */
	public SubjectType getSubjectType(){
		return subjectType;
	}
	
	/**
	 * 
	 * @return type information of subject type. variable-length vector shall have a maximum length of 32 bytes. Will return a empty byte array
	 * for a zero length subject name.
	 */
	public byte[] getSubjectName(){
		return subjectName;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(subjectType.getByteValue());
        out.write(subjectName.length); // no need for length encoding since max length > 128
        out.write(subjectName);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		subjectType = SubjectType.getByValue(in.read());
		int size = in.read();
		subjectName = new byte[size];
		in.read(subjectName);		
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(subjectName);
		result = prime * result
				+ ((subjectType == null) ? 0 : subjectType.hashCode());
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
		SubjectInfo other = (SubjectInfo) obj;
		if (!Arrays.equals(subjectName, other.subjectName))
			return false;
		if (subjectType != other.subjectType)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SubjectInfo [subjectType=" + subjectType + ", subjectName="
				+ Arrays.toString(subjectName) + "]";
	}
	
}
