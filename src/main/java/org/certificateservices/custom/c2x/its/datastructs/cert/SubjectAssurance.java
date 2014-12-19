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

import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;

/**
 * This field contains the ITS-S's assurance, which denotes the ITS-S's security of both the platform and storage of secret
 * keys as well as the confidence in this assessment.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SubjectAssurance implements StructSerializer{
	
	private int subjectAssurance;
	
	/**
	 * Contains the ITS-S's assurance, which denotes the ITS-S's security of both the platform and storage of secret
     * keys as well as the confidence in this assessment.
     * 
	 * @param assuranceLevel denotes bit fields specifying an assurance level, between 0 and 7.
	 * @param confidenceLevel enotes bit fields specifying an confidence. level, between 0 and 3.
	 * @throws IllegalArgumentException if supplied arguments where invalid.
	 */
	public SubjectAssurance(int assuranceLevel, int confidenceLevel) throws IllegalArgumentException{
		if(assuranceLevel< 0 || assuranceLevel > 7){
			throw new IllegalArgumentException("Illegal subject assurrance level, should be between 0 and 5");
		}
		if(confidenceLevel< 0 || confidenceLevel > 3){
			throw new IllegalArgumentException("Illegal subject confidence level, should be between 0 and 3");
		}
		int shiftedAssuranceLevel = assuranceLevel << 5;
		subjectAssurance = (shiftedAssuranceLevel | confidenceLevel);
	}
	
	/**
	 * Constructor used during serializing.
	 */
	public SubjectAssurance(){}
	
	/**
	 * <b>IMPORTANT</b> This method returns the subject assurance as integer due to java only have signed bytes.
	 * A serialized value should only contain a byte value.
	 * 
	 * @return the subject assurace byte built from the bitwise encoding of assuranceLevel and confidenceLevel
	 */
	public int getSubjectAssurance(){
		return subjectAssurance;
	}

	public int getAssuranceLevel(){
		return subjectAssurance >> 5;
	}
	
    public int getConfidenceLevel(){
		return subjectAssurance & 0x3;
	}

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		out.write(subjectAssurance);	
	}

	@Override
	public void deserialize(DataInputStream in) throws IOException {
		subjectAssurance = in.read();	
	}
	

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + subjectAssurance;
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
		SubjectAssurance other = (SubjectAssurance) obj;
		if (subjectAssurance != other.subjectAssurance)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SubjectAssurance [subjectAssurance=" + subjectAssurance + " (assuranceLevel=" + getAssuranceLevel() + ", confidenceLevel= " + getConfidenceLevel() +" )]";
	}
	
	

}
