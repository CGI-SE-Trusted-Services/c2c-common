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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.p2p;

import java.util.List;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;


/**
 * This class extends SequenceOfCertificate used in Ieee1609dot2Peer2PeerPDU structure.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CaCertP2pPDU extends SequenceOfCertificate {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding
	 */
	public CaCertP2pPDU() {
		super();
	}

	/**
	 * Constructor used when encoding
	 */
	public CaCertP2pPDU(Certificate[] sequenceValues) {
		super(sequenceValues);
	}

	/**
	 * Constructor used when encoding
	 */
	public CaCertP2pPDU(List<Certificate> sequenceValues) {
		super(sequenceValues);
	}
	

	@Override
	public String toString() {
		return super.toString().replace("SequenceOfCertificate", "CaCertP2pPDU");
	}
}
