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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

import java.io.IOException;

/**
 * This data structure defines the structure of Ieee1609dot2Peer2PeerPDU.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Ieee1609dot2Peer2PeerPDU extends COERSequence {
	
	public static final int DEFAULT_VERSION = 1;
	
	private static final long serialVersionUID = 1L;
	
	private static final int VERSION = 0;
	private static final int CONTENT = 1;

	/**
	 * Constructor used when decoding
	 */
	public Ieee1609dot2Peer2PeerPDU(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Ieee1609dot2Peer2PeerPDU(int version, Ieee1609dot2Peer2PeerPDUContent content) throws IOException {
		super(false,2);
		init();

		set(VERSION, new Uint8(version));
		set(CONTENT, content);
	}
	
	/**
	 * Constructor used when encoding with default version
	 */
	public Ieee1609dot2Peer2PeerPDU(Ieee1609dot2Peer2PeerPDUContent content) throws IOException {
		this(DEFAULT_VERSION,content);
	}



	/**
	 * 
	 * @return version
	 */
	public int getVersion(){
		return (int) ((Uint8) get(VERSION)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return content
	 */
	public Ieee1609dot2Peer2PeerPDUContent getContent(){
		return (Ieee1609dot2Peer2PeerPDUContent) get(CONTENT);
	}
	

	
	private void init(){
		addField(VERSION, false, new Uint8(), null);
		addField(CONTENT, false, new Ieee1609dot2Peer2PeerPDUContent(), null);
	}
	
	@Override
	public String toString() {
		return "Ieee1609dot2Peer2PeerPDU [\n" +
	   "  version=" + getVersion() + ",\n" +
	   "  content=" + getContent().toString().replace("Ieee1609dot2Peer2PeerPDUContent ", "").replaceAll("\n", "\n  ") + "\n]";
	}
	
}
