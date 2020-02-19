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
package org.certificateservices.custom.c2x.etsits102941.v131.util;

import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.*;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListRca;
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListTlm;
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.*;
/**
 * Utility class used to fetch information from a CTL such a ca certificate
 * from its name and its distribution centre URLs.
 */
public class Etsi102941CTLHelper {

    private CryptoManager cryptoManager;

    /**
     * Constructor fo Etsi102941CTLHelper
     * @param cryptoManager the crypto manager to use.
     */
    public Etsi102941CTLHelper(CryptoManager cryptoManager){
        this.cryptoManager = cryptoManager;
    }

    /**
     * Help method to build a certificate or trust store for a given set of full CTL with
     * optional deltaCTL.
     * @param fullCTL the fullCTL to extract certificates for.
     * @param deltaCTL the deltaCTL to update full CTL before populating the store.
     * @param types the types of store to build, dc type will be excluded.
     * @return a Map of id to certificate.
     * @throws IOException if encoding problems occurred.
     * @throws IllegalArgumentException if invalid CTLs was given.
     * @throws NoSuchAlgorithmException if SHA 256 digest wasn't available.
     */
    public Map<HashedId8, Certificate> buildStore(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL,
                                           CtlEntry.CtlEntryChoices[] types) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
        Map<HashedId8, Certificate> retval = new HashMap<>();

        List<CtlEntry> allEntries = getCACtlEntries(fullCTL,deltaCTL,types);
        for(CtlEntry entry : allEntries){
            Certificate cert = getCertificateFromCtlEntry(entry);
            HashedId8 certId =  cert.asHashedId8(cryptoManager);
            retval.put(certId,cert);
        }

        return retval;
    }

    /**
     * Method that fetches the CtlEntries that have a CA with matching certificateId and type.
     * @param etsiTs102941CTL the CTL to fetch all matching entries from.
     * @param type the type of CtlEntry to fetch
     * @param certificateId the certificateId to match.
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     */
    public List<CtlEntry> findCACtlEntries(EtsiTs102941CTL etsiTs102941CTL , CtlEntry.CtlEntryChoices type, CertificateId certificateId) throws IOException, NoSuchAlgorithmException {
        return findCACtlEntries(etsiTs102941CTL,null,type,certificateId);
    }

    /**
     * Method that fetches the CtlEntries that have a CA with matching certificateId and type.
     * with a combination of all delta CTL entries.
     * @param fullCTL the full CTL to fetch all matching entries from.
     * @param deltaCTL the delta CTL to fetch update entries from full CTL. Use null if no delta CTL is available.
     * @param type the type of CtlEntry to fetch
     * @param certificateId the certificateId to match.
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     */
    public List<CtlEntry> findCACtlEntries(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL, CtlEntry.CtlEntryChoices type, CertificateId certificateId) throws IOException, NoSuchAlgorithmException {
        List<CtlEntry> retval = new ArrayList<>();

        List<CtlEntry> allEntries = getCACtlEntries(fullCTL,deltaCTL,new CtlEntry.CtlEntryChoices[]{type});
        for(CtlEntry ctlEntry : allEntries){
            EtsiTs103097Certificate caCertificate = getCertificateFromCtlEntry(ctlEntry);
            if(caCertificate != null && caCertificate.getToBeSigned().getId().equals(certificateId)){
                retval.add(ctlEntry);
            }
        }

        return retval;
    }

    /**
     * Method that fetches the all CtlEntries of specified type in full and optionally delta CTL.
     * with a combination of all delta CTL entries.
     * @param fullCTL the full CTL to fetch all matching entries from.
     * @param deltaCTL the delta CTL to fetch update entries from full CTL. Use null if no delta CTL is available.
     * @param types the types of CtlEntry to fetch, DC entries are excluded
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     * @throws IllegalArgumentException if invalid CTL was specified.
     */
    public List<CtlEntry> getCACtlEntries(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL, CtlEntry.CtlEntryChoices[] types) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
        List<CtlEntry> retval = new ArrayList<>();

        Set<CtlEntry.CtlEntryChoices> typeSet = new HashSet<>();
        for(CtlEntry.CtlEntryChoices type : types){
            if(type != dc){
                typeSet.add(type);
            }
        }

        // First build from fullCTL
        CtlFormat fullCTLFormat = checkFullCTL(fullCTL);
        CtlFormat deltaCTLFormat = checkDeltaCTL(deltaCTL);

        Set<HashedId8> removedIds = new HashSet<>();
        if(deltaCTLFormat != null){
            for(CtlCommand ctlCommand : deltaCTLFormat.getCtlCommands()){
                if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.delete &&
                        ctlCommand.getCtlDelete().getType() == CtlDelete.CtlDeleteChoices.cert){
                    removedIds.add(ctlCommand.getCtlDelete().getCert());
                }
            }
        }

        for(CtlCommand ctlCommand : fullCTLFormat.getCtlCommands()){
            if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.add){
                CtlEntry ctlEntry = ctlCommand.getCtlEntry();
                if(typeSet.contains(ctlEntry.getType())){
                    HashedId8 certId = getCertificateFromCtlEntry(ctlEntry).asHashedId8(cryptoManager);
                    if(!removedIds.contains(certId)){
                        retval.add(ctlEntry);
                    }
                }
            }
        }

        if(deltaCTLFormat != null){
            for(CtlCommand ctlCommand : deltaCTLFormat.getCtlCommands()){
                if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.add){
                    CtlEntry ctlEntry  = ctlCommand.getCtlEntry();
                    if(typeSet.contains(ctlEntry.getType())){
                        retval.add(ctlEntry);
                    }
                }
            }
        }

        return retval;
    }

    /**
     * Method that fetches the all DC CtlEntries of specified type in full
     * with a combination of all delta CTL entries (Optional) for a specific certificateId
     * @param fullCTL the full CTL to fetch all valid dc entries from.
     * @param deltaCTL the delta CTL to fetch update entries from full CTL. Use null if no delta CTL is available.
     * @param certificateId the certificateId to filter out DC for.
     *
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     * @throws IllegalArgumentException if invalid CTL was specified.
     */
    public List<CtlEntry> getDCCtlEntries(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL, HashedId8 certificateId) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
        List<CtlEntry> retval = new ArrayList<>();
        List<CtlEntry> allDCEntries = getDCCtlEntries(fullCTL,deltaCTL);
        for(CtlEntry ctlEntry : allDCEntries){
            COEREncodable[] values = ctlEntry.getDcEntry().getCert().getSequenceValues();
            for(COEREncodable value : values){
                if(value.equals(certificateId)){
                    retval.add(ctlEntry);
                }
            }
        }
        return retval;
    }

    /**
     * Method that fetches the all DC CtlEntries of specified type in full
     * with a combination of all delta CTL entries (Optional).
     * @param fullCTL the full CTL to fetch all valid dc entries from.
     * @param deltaCTL the delta CTL to fetch update entries from full CTL. Use null if no delta CTL is available.
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     * @throws IllegalArgumentException if invalid CTL was specified.
     */
    public List<CtlEntry> getDCCtlEntries(EtsiTs102941CTL fullCTL, EtsiTs102941CTL deltaCTL) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
        List<CtlEntry> retval = new ArrayList<>();

        // First build from fullCTL
        CtlFormat fullCTLFormat = checkFullCTL(fullCTL);
        CtlFormat deltaCTLFormat = checkDeltaCTL(deltaCTL);

        Set<String> removedIds = new HashSet<>();
        if(deltaCTLFormat != null){
            for(CtlCommand ctlCommand : deltaCTLFormat.getCtlCommands()){
                if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.delete &&
                        ctlCommand.getCtlDelete().getType() == CtlDelete.CtlDeleteChoices.dc){
                    removedIds.add(ctlCommand.getCtlDelete().getDc().getUrl());
                }
            }
        }

        for(CtlCommand ctlCommand : fullCTLFormat.getCtlCommands()){
            if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.add){
                CtlEntry ctlEntry = ctlCommand.getCtlEntry();
                if(ctlEntry.getType() == dc){
                    if(!removedIds.contains(ctlEntry.getDcEntry().getUrl().getUrl())){
                        retval.add(ctlEntry);
                    }
                }
            }
        }

        if(deltaCTLFormat != null){
            for(CtlCommand ctlCommand : deltaCTLFormat.getCtlCommands()){
                if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.add){
                    CtlEntry ctlEntry  = ctlCommand.getCtlEntry();
                    if(ctlEntry.getType() == dc){
                        retval.add(ctlEntry);
                    }
                }
            }
        }

        return retval;
    }

    /**
     * Help method to fetch the inner CTL format from the CTL, supports both RCACTL and TLMCTL
     * @param etsiTs102941CTL the CTL to parse.
     * @return the ctlFormat object of the inner EtsiTs102941Data.
     * @throws IOException if decoding problems occurred.
     */
    public CtlFormat getCtlFormat(EtsiTs102941CTL etsiTs102941CTL) throws IOException{
        Ieee1609Dot2Data innerData = ((SignedData) etsiTs102941CTL.getContent().getValue()).getTbsData().getPayload().getData();
        Opaque opaque = (Opaque) innerData.getContent().getValue();
        EtsiTs102941Data toBeSignedCtl = new EtsiTs102941Data(opaque.getData());
        if(toBeSignedCtl.getContent().getType() == certificateTrustListRca){
            return toBeSignedCtl.getContent().getToBeSignedRcaCtl();
        }
        if(toBeSignedCtl.getContent().getType() == certificateTrustListTlm){
            return toBeSignedCtl.getContent().getToBeSignedTlmCtl();
        }
        throw new IOException("Invalid data structure, verify that data is of type certificateTrustListRca or certificateTrustListTlm.");
    }

    /**
     * Help method to fetch the matching certificate from CTLEntry depending on type.
     * For rca and tlm is the self-signed certificate fetched.
     * @param ctlEntry the ctlEntry to parse.
     * @return the related certificate or null.
     */
    private EtsiTs103097Certificate getCertificateFromCtlEntry(CtlEntry ctlEntry){
        if(ctlEntry.getType() == aa){
            return ctlEntry.getAaEntry().getAaCertificate();
        }
        if(ctlEntry.getType() == ea){
            return ctlEntry.getEaEntry().getEaCertificate();
        }
        if(ctlEntry.getType() == rca){
            return ctlEntry.getRcaEntry().getSelfsignedRootCa();
        }
        if(ctlEntry.getType() == tlm){
            return ctlEntry.getTlmEntry().getSelfSignedTLMCertificate();
        }

        return null;
    }

    /**
     * Method to check if a CTL was a full CTL and not delta CTL.
     * @param fullCTL ctl to check
     * @return the inner CTL Format
     * @throws IllegalArgumentException if given CTL was not a full CTL
     * @throws IOException if encoding problems occurred
     */
    private CtlFormat checkFullCTL(EtsiTs102941CTL fullCTL) throws IllegalArgumentException, IOException {
        CtlFormat fullCTLFormat = getCtlFormat(fullCTL);
        if(!fullCTLFormat.isFullCtl()){
            throw new IllegalArgumentException("Invalid fullCTL specified when building certificate store, it should not be a delta CTL.");
        }
        return fullCTLFormat;
    }

    /**
     * Method to check if a CTL was a delta CTL and not full CTL.
     * @param deltaCTL ctl to check
     * @return the inner CTL Format
     * @throws IllegalArgumentException if given CTL was not a delta CTL
     * @throws IOException if encoding problems occurred
     */
    private CtlFormat checkDeltaCTL(EtsiTs102941CTL deltaCTL) throws IllegalArgumentException, IOException{
        CtlFormat deltaCTLFormat = null;
        if(deltaCTL != null) {
            deltaCTLFormat = getCtlFormat(deltaCTL);
            if (deltaCTLFormat.isFullCtl()) {
                throw new IllegalArgumentException("Invalid deltaCTL specified when building certificate store, it should not be a full CTL.");
            }
        }
        return deltaCTLFormat;
    }

}
