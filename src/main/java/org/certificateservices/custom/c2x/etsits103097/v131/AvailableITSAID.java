package org.certificateservices.custom.c2x.etsits103097.v131;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;

/**
 * Contains Defined ITS AID constants according to 102 965 V1.4.1
 *
 * @author Philip Vendil p.vendil@cgi.com
 */
public class AvailableITSAID {

    /**
     * CA basic service is specified in
     * ETSI EN 302 637-2 [i.2]
     */
    public static Psid CABasicService = new Psid(36);

    /**
     * DEN basic service is specified in
     * ETSI EN 302 637-3 [i.3]
     */
    public static Psid DENBasicService = new Psid(37);

    /**
     * TLM service as specified in
     * ETSI TS 103 301 [i.4]
     */
    public static Psid TLMService = new Psid(137);

    /**
     * RLT service as specified in
     * ETSI TS 103 301 [i.4]
     */
    public static Psid RLTService = new Psid(138);

    /**
     * IVI service as specified in
     * ETSI TS 103 301 [i.4]
     */
    public static Psid IVIService = new Psid(139);

    /**
     * TLC service as specified in
     * ETSI TS 103 301 [i.4]
     */
    public static Psid TLCService = new Psid(140);

    /**
     * GeoNetworking Management
     * Communications as specified in
     * ETSI EN 302 636-4-1 [i.5]
     */
    public static Psid GeoNetworkingManagementCommunications  = new Psid(141);

    /**
     * SA service as specified in
     * ETSI EN 302 890-1 [i.6]
     */
    public static Psid SAService  = new Psid(540801);

    /**
     * CRL service as specified in ETSI
     * TS 102 941 [i.7]
     */
    public static Psid CRLService   = new Psid(622);

    /**
     * Secure certificate request service
     * as specified in ETSI
     * TS 102 941 [i.7]
     */
    public static Psid SecuredCertificateRequestService  = new Psid(623);

    /**
     * CTL service as specified in ETSI
     * TS 102 941 [i.7]
     */
    public static Psid CTLService   = new Psid(624);

    /**
     * GPC service as specified in
     * ETSI TS 103 301 [i.4]
     */
    public static Psid GPCService   = new Psid(540802);

}
