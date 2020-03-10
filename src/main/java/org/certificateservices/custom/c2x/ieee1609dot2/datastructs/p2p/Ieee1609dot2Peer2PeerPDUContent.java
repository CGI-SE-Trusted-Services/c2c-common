/************************************************************************
 *                                                                       *
 3 *  Certificate Service -  Car2Car Core                                  *
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

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;

/**
 * This data structure defines the content choice structure in Ieee1609dot2Peer2PeerPDU.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Ieee1609dot2Peer2PeerPDUContent extends COERChoice {


	private static final long serialVersionUID = 1L;

	public enum Ieee1609dot2Peer2PeerPDUContentChoices implements COERChoiceEnumeration{
		caCerts;

		@Override
		public COEREncodable getEmptyCOEREncodable()  {
			switch (this) {
				case caCerts:
				default:
					return new CaCertP2pPDU();

			}
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}

	/**
	 * Constructor used when decoding.
	 */
	public Ieee1609dot2Peer2PeerPDUContent() {
		super(Ieee1609dot2Peer2PeerPDUContentChoices.class);
	}

	/**
	 * Constructor used when encoding of type caCerts
	 */
	public Ieee1609dot2Peer2PeerPDUContent(CaCertP2pPDU caCertP2pPDU) {
		super(Ieee1609dot2Peer2PeerPDUContentChoices.caCerts, caCertP2pPDU);
	}


	/**
	 * Returns the type of id.
	 */
	public Ieee1609dot2Peer2PeerPDUContentChoices getType(){
		return (Ieee1609dot2Peer2PeerPDUContentChoices) choice;
	}

	@Override
	public String toString() {
		switch (getType()) {
			case caCerts:
				return "Ieee1609dot2Peer2PeerPDUContent [" + choice + "=" + value.toString().replace("CaCertP2pPDU ", "") +"]";
			default:
				return "Ieee1609dot2Peer2PeerPDUContent [" + choice + "]";
		}

	}

}
