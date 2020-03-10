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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * This field contains the certificate holder's assurance level, which indicates the security of both the platform and 
 * storage of secret keys as well as the confidence in this assessment.
 * <p>
 * This field is encoded as defined in table 5, where "A" denotes bit fields specifying an assurance level, 
 * "R" reserved bit fields and "C" bit fields specifying the confidence.
 * <p>
 * In table 5, bit number 0 denotes the least significant bit. Bit 7 to bit 5 denote the device's assurance levels, 
 * bit 4 to bit 2 are reserved for future use and bit 1 and bit 0 denote the confidence.
 * <p>
 * The specification of these assurance levels as well as the encoding of the confidence levels is outside the scope of 
 * the present document. It can be assumed that a higher assurance value indicates that the holder is more trusted than the holder 
 * of a certificate lower assurance value and the same confidence value.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SubjectAssurance extends COEROctetStream {
	
	private static final int OCTETSTRING_SIZE = 1;
	
	private static final long serialVersionUID = 1L;
	
	private Integer subjectAssurance = null;
	
	/**
	 * Constructor used when decoding
	 */
	public SubjectAssurance(){
		super(OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	}
	
	/**
	 * Contains the ITS-S's assurance, which denotes the ITS-S's security of both the platform and storage of secret
     * keys as well as the confidence in this assessment.
     * 
	 * @param assuranceLevel denotes bit fields specifying an assurance level, between 0 and 7.
	 * @param confidenceLevel denotes bit fields specifying an confidence. level, between 0 and 3.
	 * @throws IOException if supplied arguments where invalid.
	 */
	public SubjectAssurance(int assuranceLevel, int confidenceLevel) throws IOException{
		super(OCTETSTRING_SIZE, OCTETSTRING_SIZE);
		if(assuranceLevel< 0 || assuranceLevel > 7){
			throw new IOException("Illegal subject assurance level, should be between 0 and 7");
		}
		if(confidenceLevel< 0 || confidenceLevel > 3){
			throw new IOException("Illegal subject confidence level, should be between 0 and 3");
		}
		int shiftedAssuranceLevel = assuranceLevel << 5;
		subjectAssurance = (shiftedAssuranceLevel | confidenceLevel);
		data = new byte[1];
		data[0] = ByteBuffer.allocate(4).putInt(subjectAssurance).get(3);
	}

	/**
	 * <b>IMPORTANT</b> This method returns the subject assurance as integer due to java only have signed bytes.
	 * A serialized value should only contain a byte value.
	 * 
	 * @return the subject assurace byte built from the bitwise encoding of assuranceLevel and confidenceLevel
	 */
	public int getSubjectAssurance(){
		if(subjectAssurance == null){
			byte[] intData = new byte[4];
			intData[3] = data[0];
			ByteBuffer byteBuffer = ByteBuffer.allocate(4);
			byteBuffer.put(intData);
			byteBuffer.position(0);

			subjectAssurance = byteBuffer.asIntBuffer().get();
		}
		return subjectAssurance;
	}

	public int getAssuranceLevel(){
		return getSubjectAssurance() >> 5;
	}
	
    public int getConfidenceLevel(){
		return getSubjectAssurance() & 0x3;
	}
	
	@Override
	public String toString() {
		return "SubjectAssurance [subjectAssurance=" + getSubjectAssurance() + " (assuranceLevel=" + getAssuranceLevel() + ", confidenceLevel= " + getConfidenceLevel() +" )]";
	}
	
	

}
