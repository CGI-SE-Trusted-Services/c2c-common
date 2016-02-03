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
package org.certificateservices.custom.c2x.ieee1609dot2.crl.basic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time32;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Uint8;

/**
 * In this structure:
 * 
 * <li>version is the version number of the CRL. For this version of this standard it is 1.
 * <li>crlSeries represents the CRL series to which this CRL belongs. This is used to determine whether 
 * the revocation information in a CRL is relevant to a particular certificate as specified in 5.1.3.2.
 * <li>cracaId contains the low-order eight octets of the hash of the certificate of the Certificate 
 * Revocation Authorization CA (CRACA) that ultimately authorized the issuance of this CRL. This is used to 
 * determine whether the revocation information in a CRL is relevant to a particular certificate as specified 
 * in 5.1.3.2. In a valid signed CRL as specified in 7.4 the cracaId is consistent with the associatedCraca 
 * field in the Service Specific Permissions as defined in 7.4.3.3.
 * <li>issueDate specifies the time when the CRL was issued.
 * <li>nextCrl contains the time when the next CRL with the same crlSeries and cracaId is expected to be issued. 
 * The CRL is invalid unless nextCrl is strictly after issueDate. This field is used to set the expected
 * update time for revocation information associated with the (cracaId, crlSeries) pair as specified in 5.1.3.6.
 * <li>priorityInfo contains information that assists devices with limited storage space in determining which 
 * revocation information to retain and which to discard.
 * <li>typeSpecific contains the CRL body:
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlContents extends COERSequence {
	
	public static final int DEFAULT_VERSION = 1;
	
	private static final long serialVersionUID = 1L;
	
	private static final int VERSION = 0;
	private static final int CRLSERIES = 1;
	private static final int CRACAID = 2;
	private static final int ISSUEDATE = 3;
	private static final int NEXTCRL = 4;
	private static final int PRIORITYINFO = 5;
	private static final int TYPESPECIFIC = 6;

	/**
	 * Constructor used when decoding
	 */
	public CrlContents(){
		super(false,7);
		init();
	}
	
	/**
	 * Constructor used when encoding and default version
	 */
	public CrlContents(CrlSeries crlSeries, HashedId8  cracaId,Time32 issueDate, Time32  nextCrl,
			CrlPriorityInfo priorityInfo, CrlContentsType typeSpecific){
		this(DEFAULT_VERSION, crlSeries, cracaId, issueDate, nextCrl, priorityInfo, typeSpecific);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CrlContents(int version, CrlSeries crlSeries, HashedId8  cracaId,Time32 issueDate, Time32  nextCrl,
			CrlPriorityInfo priorityInfo, CrlContentsType typeSpecific){
		super(false,7);
		init();
		set(VERSION, new Uint8(version));
		set(CRLSERIES, crlSeries);
		set(CRACAID, cracaId);
		set(ISSUEDATE, issueDate);
		set(NEXTCRL, nextCrl);
		set(PRIORITYINFO, priorityInfo);
		set(TYPESPECIFIC, typeSpecific);
	}
	
	/**
	 * Constructor decoding a CrlContents from an encoded byte array.
	 * @param encodedData byte array encoding of the CrlContents.
	 * @throws IOException   if communication problems occurred during serialization.
	 */
	public CrlContents(byte[] encodedData) throws IOException{
		super(false,7);
		init();
		
		DataInputStream dis = new DataInputStream(new  ByteArrayInputStream(encodedData));
		decode(dis);
	}

	/**
	 * 
	 * @return Returns the version value
	 */
	public int getVersion(){
		return (int) ((Uint8) get(VERSION)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the crlSeries value
	 */
	public CrlSeries getCrlSeries(){
		return (CrlSeries) get(CRLSERIES);
	}
	
	
	/**
	 * 
	 * @return Returns the cracaId value
	 */
	public HashedId8 getCracaId(){
		return (HashedId8) get(CRACAID);
	}
	
	/**
	 * 
	 * @return Returns the issueDate value
	 */
	public Time32 getIssueDate(){
		return (Time32) get(ISSUEDATE);
	}
	
	/**
	 * 
	 * @return Returns the nextCrl value
	 */
	public Time32 getNextCrl(){
		return (Time32) get(NEXTCRL);
	}
	
	/**
	 * 
	 * @return Returns the priorityInfo value
	 */
	public CrlPriorityInfo getPriorityInfo(){
		return (CrlPriorityInfo) get(PRIORITYINFO);
	}
	
	/**
	 * 
	 * @return Returns the typeSpecific value
	 */
	public CrlContentsType getTypeSpecific(){
		return (CrlContentsType) get(TYPESPECIFIC);
	}
	
	/**
	 * Encodes the CrlContents as a byte array.
	 * 
	 * @return return encoded version of the CrlContents as a byte[] 
	 * @throws IOException if encoding problems of the data occurred.
	 */
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		encode(dos);
		return baos.toByteArray();		
	}
	
	private void init(){
		addField(VERSION, false, new Uint8(), null);
		addField(CRLSERIES, false, new CrlSeries(), null);
		addField(CRACAID, false, new HashedId8(), null);
		addField(ISSUEDATE, false, new Time32(), null);
		addField(NEXTCRL, false, new Time32(), null);
		addField(PRIORITYINFO, false, new CrlPriorityInfo(), null);
		addField(TYPESPECIFIC, false, new CrlContentsType(), null);
	}
	

	@Override
	public String toString() {
		return "CrlContents [\n" +
	"  version=" + getVersion() + ",\n" +
	"  crlSeries=" + getCrlSeries().toString().replace("CrlSeries ", "") + ",\n" +
	"  cracaId=" + getCracaId().toString().replace("HashedId8", "") + ",\n" +
	"  issueDate=" + getIssueDate().toString().replace("Time32 ", "") + ",\n" +
	"  nextCrl=" + getNextCrl().toString().replace("Time32 ", "")  + ",\n" +
	"  priorityInfo=" + getPriorityInfo().toString().replace("CrlPriorityInfo ", "")  + ",\n" +
	"  typeSpecific=" + getTypeSpecific().toString().replace("CrlContentsType ","").replaceAll("\n","\n  ")  + "\n" +
	"]";
	}
	
}
