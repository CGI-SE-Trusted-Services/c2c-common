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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv;

import java.io.DataInputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContents;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;

/**
 * Special form of Ieee1609Dot2Data with specified fields to fulfill the requirements
 * of a secured crl.
 * <p>
 * See SecuredCRLGenerator class for methods on how to create a CRL. 
 *
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredCrl extends Ieee1609Dot2Data {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SecuredCrl(){
		super();
	}
	
	/**
	 * Constructor used when encoding using default protocol version
	 */
	public SecuredCrl(Ieee1609Dot2Content content) throws IOException{
		this(DEFAULT_VERSION, content);
	}
	
	/**
	 * Constructor converting a Ieee1609Dot2Data to a secured crl and verifies the requirements
	 */
	public SecuredCrl(Ieee1609Dot2Data data) throws IOException{
		this(data.getProtocolVersion(), data.getContent());
		
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a secured crl");
		}
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SecuredCrl(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
		super(protocolVersion,content);

		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a secured crl");
		}
	}
	
	/**
	 * Constructor decoding a secured crl from an encoded byte array.
	 * @param encodedData byte array encoding of the Ieee1609Dot2Data.
	 * @throws IOException  if communication problems occurred during serialization.
	 */
	public SecuredCrl(byte[] encodedData) throws IOException{
		super(encodedData);
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a secured crl");
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
		if(sdp.getData() == null || sdp.getData().getContent() == null){
			return false;
		}
		Ieee1609Dot2Content unsignedContent = sdp.getData().getContent();
		if(unsignedContent.getType() != Ieee1609Dot2ContentChoices.unsecuredData){
			return false;
		}
		
		HeaderInfo hi = sd.getTbsData().getHeaderInfo();
		if(hi.getGenerationTime() != null 
				|| hi.getExpiryTime() != null
				|| hi.getGenerationLocation() != null
				|| hi.getP2pcdLearningRequest() != null
				|| hi.getMissingCrlIdentifier() != null
				|| hi.getEncryptionKey() != null){
			return false;
		}
		if(hi.getPsid().getValueAsLong() != CrlPsid.PSID){
			return false;
		}
		
		return true;
	}
	
	/**
	 * 
	 * @return help method that parses the CRL Contents from the Secure CRL
	 * @throws IOException if serialization problems occurred.
	 */
	public CrlContents getCrlContents() throws IOException{
		SignedDataPayload sdp = ((SignedData) getContent().getValue()).getTbsData().getPayload();
		Opaque o = (Opaque) sdp.getData().getContent().getValue();
		
		return new CrlContents(o.getData());
		
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.asn1.coer.COERSequence#decode(java.io.DataInputStream)
	 */
	@Override
	public void decode(DataInputStream in) throws IOException {
		super.decode(in);
		if(!fullfillsRequirements(this)){
			throw new IOException("Error Ieee1609Dot2Data content doesn't fullfill requirments of a secured crl");
		}
	}

	@Override
	public String toString() {
		return "SecuredCrl [\n" +
	    "  protocolVersion=" + getProtocolVersion() + ",\n" +
	    "  content=" + getContent().toString().replace("Ieee1609Dot2Content ", "").replaceAll("\n", "\n  ")  + 
	    "\n]";
	}
	
}
