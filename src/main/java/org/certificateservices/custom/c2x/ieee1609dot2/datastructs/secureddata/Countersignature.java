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

import java.io.DataInputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;

/**
 * This data structure is used to perform a countersignature over an already-signed SPDU. This is the profile
 * of an Ieee1609Dot2Data containing a signedData. The tbsData within content is composed of a payload
 * containing the hash (extDataHash) of the externally generated, pre-signed SPDU over which the
 * countersignature is performed.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Countersignature extends Ieee1609Dot2Data {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Countersignature(){
		super();
	}
	
	/**
	 * Constructor used when encoding using default protocol version
	 */
	public Countersignature(Ieee1609Dot2Content content) throws IOException{
		this(DEFAULT_VERSION, content);
	}
	
	/**
	 * Constructor converting a Ieee1609Dot2Data to a Countersignature and verifies the requirements
	 */
	public Countersignature(Ieee1609Dot2Data data) throws IOException{
		this(data.getProtocolVersion(), data.getContent());
		
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a Countersignature");
		}
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Countersignature(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
		super(protocolVersion,content);

		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a Countersignature");
		}
	}
	
	/**
	 * Constructor decoding a Countersignature from an encoded byte array.
	 * @param encodedData byte array encoding of the Ieee1609Dot2Data.
	 * @throws IOException  if communication problems occurred during serialization.
	 */
	public Countersignature(byte[] encodedData) throws IOException{
		super(encodedData);
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a Countersignature");
		}
	}

	/**
	 * Method that verifies all the requirements of a counter signature.
	 */
	public static boolean fullfillsRequirements(Ieee1609Dot2Data data) {
		Ieee1609Dot2Content content = data.getContent();
		if(content.getType() != Ieee1609Dot2ContentChoices.signedData){
			return false;
		}
		
		SignedData sd = (SignedData) content.getValue();
		SignedDataPayload sdp = sd.getTbsData().getPayload();
		if(sdp.getData() != null || sdp.getExtDataHash() == null){
			return false;
		}
		HeaderInfo hi = sd.getTbsData().getHeaderInfo();
		if(hi.getGenerationTime() == null 
				|| hi.getExpiryTime() != null
				|| hi.getGenerationLocation() != null
				|| hi.getP2pcdLearningRequest() != null
				|| hi.getMissingCrlIdentifier() != null
				|| hi.getEncryptionKey() != null){
			return false;
		}
		
		return true;
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.asn1.coer.COERSequence#decode(java.io.DataInputStream)
	 */
	@Override
	public void decode(DataInputStream in) throws IOException {
		super.decode(in);
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a Countersignature");
		}
	}

	@Override
	public String toString() {
		return "Countersignature [\n" +
	    "  protocolVersion=" + getProtocolVersion() + ",\n" +
	    "  content=" + getContent().toString().replace("Ieee1609Dot2Content ", "").replaceAll("\n", "\n  ")  + 
	    "\n]";
	}
	
}
