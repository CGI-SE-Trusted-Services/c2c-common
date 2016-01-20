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
package org.certificateservices.custom.c2x.ieee1609dot2.secureddata;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time64;

/**
 * This structure contains information that is used to establish validity by the criteria of 5.2.
 * <p>
 * <li>psid indicates the application area with which the sender is claiming the payload should be associated.
 * <li>generationTime indicates the time at which the structure was generated. See 5.2.4.2.2, 5.2.4.2.3 for discussion of the use of this field.
 * <li>expiryTime, if present, contains the time after which the data should no longer be considered relevant. If both generationTime and expiryTime are present, the signed SPDU is invalid if generationTime is not strictly earlier than expiryTime.
 * <li>generationLocation, if present, contains the location at which the signature was generated.
 * <li>p2pcdLearningRequest, if present, is used by the SDS to request certificates for which it has seen identifiers but do not know the entire certificate. A specification of this peer-to-peer certificate distribution mechanism is given in 8.
 * <li>missingCrlIdentifier, if present, is used by the SDS to request CRLs which it knows to have been issued but have not received. This is provided for future use and the associated mechanism is not defined in this version of this standard.
 * <li>encryptionKey, if present, is used to indicate that a further communcation should be encrypted with the indicated key. One possible use of this key to encrypt a response is specified in 6.3.31, 6.3.32, 6.3.34. An encryptionKey field of type symmetric should only be used if the Signed- Data containing this field is securely encrypted by some means.
 * <p>
 * <b>ENCODING CONSIDERATIONS:</b>When the structure is encoded in order to be digested to generate or
 * check a signature, if encryptionKey is present, and indicates the choice public, and contains a
 * BasePublicEncryptionKey that is an elliptic curve point (i.e. that is of typeEccP256CurvePoint) , then the
 * elliptic curve point is encoded in compressed form, i.e. such that the choice indicated within the
 * EccP256CurvePoint is compressed-y-0 or compressed-y-1.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HeaderInfo extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int PSID = 0;
	private static final int GENERATIONTIME = 1;
	private static final int EXPIRYTIME = 2;
	private static final int GENERATIONLOCATION = 3;
	private static final int P2PCDLEARNINGREQUEST = 4;
	private static final int MISSINGCRLIDENTIFIER = 5;
	private static final int ENCRYPTIONKEY = 6;

	/**
	 * Constructor used when decoding
	 */
	public HeaderInfo(){
		super(true,7);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public HeaderInfo(Psid psid, Time64 generationTime, Time64 expiryTime, ThreeDLocation generationLocation,
			HashedId3 p2pcdLearningRequest, MissingCrlIdentifier missingCrlIdentifier, EncryptionKey encryptionKey){
		super(true,7);
		init();
		set(PSID, psid);
		set(GENERATIONTIME, generationTime);
		set(EXPIRYTIME, expiryTime);
		set(GENERATIONLOCATION, generationLocation);
		set(P2PCDLEARNINGREQUEST, p2pcdLearningRequest);
		set(MISSINGCRLIDENTIFIER, missingCrlIdentifier);
		set(ENCRYPTIONKEY, encryptionKey);
	
	}

	/**
	 * 
	 * @return psid, required
	 */
	public Psid getPsid(){
		return (Psid) get(PSID);
	}
	
	/**
	 * 
	 * @return generationTime, optional, null if not set
	 */
	public Time64 getGenerationTime(){
		return (Time64) get(GENERATIONTIME);
	}
	
	/**
	 * 
	 * @return expiryTime, optional, null if not set
	 */
	public Time64 getExpiryTime(){
		return (Time64) get(EXPIRYTIME);
	}
	
	/**
	 * 
	 * @return generationLocation, optional, null if not set
	 */
	public ThreeDLocation getGenerationLocation(){
		return (ThreeDLocation) get(GENERATIONLOCATION);
	}
	
	/**
	 * 
	 * @return p2pcdLearningRequest, optional, null if not set
	 */
	public HashedId3 getP2pcdLearningRequest(){
		return (HashedId3) get(P2PCDLEARNINGREQUEST);
	}
	
	/**
	 * 
	 * @return missingCrlIdentifier, optional, null if not set
	 */
	public MissingCrlIdentifier getMissingCrlIdentifier(){
		return (MissingCrlIdentifier) get(MISSINGCRLIDENTIFIER);
	}
	
	/**
	 * 
	 * @return encryptionKey, optional, null if not set
	 */
	public EncryptionKey getEncryptionKey(){
		return (EncryptionKey) get(ENCRYPTIONKEY);
	}
	
	private void init(){
		addField(PSID, false, new Psid(), null);
		addField(GENERATIONTIME, true, new Time64(), null);
		addField(EXPIRYTIME, true, new Time64(), null);
		addField(GENERATIONLOCATION, true, new ThreeDLocation(), null);
		addField(P2PCDLEARNINGREQUEST, true, new HashedId3(), null);
		addField(MISSINGCRLIDENTIFIER, true, new MissingCrlIdentifier(), null);
		addField(ENCRYPTIONKEY, true, new EncryptionKey(), null);
	}
	
	@Override
	public String toString() {
		String retval = "HeaderInfo [\n"+
	    "  psid=" + getPsid().toString().replace("Psid ", "") +  ",\n"+
		(getGenerationTime() != null ? "  generationTime=" + getGenerationTime().toString().replace("Time64 ", "")   +  ",\n" : "") +
		(getExpiryTime() != null ? "  expiryTime=" + getExpiryTime().toString().replace("Time64 ", "")   +  ",\n" : "") +
	    (getGenerationLocation() != null ? "  generationLocation=" + getGenerationLocation().toString().replace("ThreeDLocation ", "")   +  ",\n" : "")+
	    (getP2pcdLearningRequest() != null ? "  p2pcdLearningRequest=" + getP2pcdLearningRequest().toString().replace("HashedId3 ", "")   +  ",\n" : "")+
	    (getMissingCrlIdentifier() != null ? "  missingCrlIdentifier=" + getMissingCrlIdentifier().toString().replace("MissingCrlIdentifier ", "")   +  ",\n" : "")+
	    (getEncryptionKey() != null ? "  encryptionKey=" + getEncryptionKey().toString().replace("EncryptionKey ", "")   +  "\n" : "")+
		"]";
		if(retval.endsWith(",\n]")){
			retval = retval.substring(0, retval.length()-3) + "\n]";
		}
		return retval;
	}
	
}
