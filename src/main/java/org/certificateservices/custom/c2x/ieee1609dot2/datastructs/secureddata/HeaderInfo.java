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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

import java.io.IOException;

/**
 * This structure contains information that is used to establish validity by the criteria of 5.2.
 * <p>
 * <ul>
 * <li>psid indicates the application area with which the sender is claiming the payload should be associated.</li>
 * <li>generationTime indicates the time at which the structure was generated. See 5.2.4.2.2, 5.2.4.2.3 for discussion of the use of this field.</li>
 * <li>expiryTime, if present, contains the time after which the data should no longer be considered relevant. If both generationTime and expiryTime are present, the signed SPDU is invalid if generationTime is not strictly earlier than expiryTime.</li>
 * <li>generationLocation, if present, contains the location at which the signature was generated.</li>
 * <li>p2pcdLearningRequest, if present, is used by the SDS to request certificates for which it has
 * seen identifiers but dodoes not know the entire certificate. A specification of this peer-to-peer
 * certificate distribution (P2PCD) mechanism is given in Clause 8. This field is used for the out-ofband
 * flavor of P2PCD and shall only be present if inlineP2pcdRequest is not present. The
 * HashedId3 is calculated with the whole-certificate hash algorithm, determined as described in 6.4.3.</li>
 * <li>missingCrlIdentifier, if present, is used by the SDS to request CRLs which it knows to
 * have been issued but havehas not received. This is provided for future use and the associated
 * mechanism is not defined in this version of this standard.</li>
 * <li>encryptionKey, with the indicated key. One possible use of this key to encrypt a response is
 * specified in 6.3.33, 6.3.34, and6.3.36. An encryptionKey field of type symmetric should only
 * be used if the SignedData containing this field is securely encrypted by some means.</li>
 * <li>inlineP2pcdRequest,if present, is used by the SDS to request unknown certificates per the
 * inline peer-to-peer certificate distribution mechanism is given in Clause 8. This field shall only be
 * present if p2pcdLearningRequest is not present. The HashedId3 is calculated with the wholecertificate
 * hash algorithm, determined as described in 6.4.3.</li>
 * <li>requestedCertificate, if present, is used by the SDS to provide certificates per the "inline"
 * version of the peer-to-peer certificate distribution mechanism given in Clause 8.</li>
 * </ul>
 * <p>
 * <b>ENCODING CONSIDERATIONS:</b>When the structure is encoded in order to be digested to generate or check a
 * signature, if encryptionKey is present, and indicates the choice public, and contains a
 * BasePublicEncryptionKey that is an elliptic curve point (i.e., of type EccP256CurvePoint or
 * EccP384CurvePoint), then the elliptic curve point is encoded in compressed form, i.e., such that the choice
 * indicated within the EccP256CurvePointEcc*CurvePoint is compressed-y-0 or compressed-y-1.
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
	private static final int INLINEP2PCDREQUEST = 0;
	private static final int REQUESTEDCERTIFICATE = 1;

	/**
	 * Constructor used when decoding
	 */
	public HeaderInfo(){
		super(true,9);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public HeaderInfo(Psid psid, Time64 generationTime, Time64 expiryTime, ThreeDLocation generationLocation,
			HashedId3 p2pcdLearningRequest, MissingCrlIdentifier missingCrlIdentifier, EncryptionKey encryptionKey,
					  SequenceOfHashedId3 inlineP2pcdRequest, Certificate requestedCertificate) throws IOException {
		super(true,7);
		init();
		set(PSID, psid);
		set(GENERATIONTIME, generationTime);
		set(EXPIRYTIME, expiryTime);
		set(GENERATIONLOCATION, generationLocation);
		set(P2PCDLEARNINGREQUEST, p2pcdLearningRequest);
		set(MISSINGCRLIDENTIFIER, missingCrlIdentifier);
		set(ENCRYPTIONKEY, encryptionKey);
		setExtension(INLINEP2PCDREQUEST, inlineP2pcdRequest);
		setExtension(REQUESTEDCERTIFICATE, requestedCertificate);
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

	/**
	 *
	 * @return inlineP2pcdRequest, optional, null if not set
	 */
	public SequenceOfHashedId3 getInlineP2pcdRequest(){
		return (SequenceOfHashedId3) getExtension(INLINEP2PCDREQUEST);
	}

	/**
	 *
	 * @return requestedCertificate, optional, null if not set
	 */
	public Certificate getRequestedCertificate(){
		return (Certificate) getExtension(REQUESTEDCERTIFICATE);
	}
	
	private void init(){
		addField(PSID, false, new Psid(), null);
		addField(GENERATIONTIME, true, new Time64(), null);
		addField(EXPIRYTIME, true, new Time64(), null);
		addField(GENERATIONLOCATION, true, new ThreeDLocation(), null);
		addField(P2PCDLEARNINGREQUEST, true, new HashedId3(), null);
		addField(MISSINGCRLIDENTIFIER, true, new MissingCrlIdentifier(), null);
		addField(ENCRYPTIONKEY, true, new EncryptionKey(), null);
		addExtension(INLINEP2PCDREQUEST, true, new SequenceOfHashedId3(), null);
		addExtension(REQUESTEDCERTIFICATE, true, new Certificate(), null);
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
	    (getEncryptionKey() != null ? "  encryptionKey=" + getEncryptionKey().toString().replace("EncryptionKey ", "")   +  ",\n" : "")+
		(getInlineP2pcdRequest() != null ? "  inlineP2pcdRequest=" + getInlineP2pcdRequest().toString().replace("SequenceOfHashedId3 ", "")   +  ",\n" : "")+
		(getRequestedCertificate() != null ? "  requestedCertificate=" + getRequestedCertificate().toString().replace("EtsiTs103097Certificate ","").replace("Certificate ", "").replaceAll("\n","\n  ")   +  "\n" : "")+
		"]";
		if(retval.endsWith(",\n]")){
			retval = retval.substring(0, retval.length()-3) + "\n]";
		}
		return retval;
	}
	
}
