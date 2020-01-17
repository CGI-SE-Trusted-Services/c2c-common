package org.certificateservices.custom.c2x.etsits102941.v131.util;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListRca;
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListTlm;
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.*;
/**
 * Utility class used to fetch information from a CTL such a ca certificate
 * from its name and its distribution centre URLs.
 */
public class Etsi102941CTLHelper {

    /**
     * Method that fetches the CtlEntries that have a CA with matching certificateId and type.
     * @param etsiTs102941CTL the CTL to fetch all matching entries from.
     * @param type the type of CtlEntry to fetch
     * @param certificateId the certificateId to match.
     * @return a list of all matching entries, empty list if none found.
     * @throws IOException if decoding problems occurred reading the CTL
     */
    List<CtlEntry> findCACtlEntries(EtsiTs102941CTL etsiTs102941CTL , CtlEntry.CtlEntryChoices type, CertificateId certificateId) throws IOException{
        List<CtlEntry> retval = new ArrayList<>();

        CtlFormat ctlFormat = getCtlFormat(etsiTs102941CTL);
        for(CtlCommand ctlCommand : ctlFormat.getCtlCommands()){
            if(ctlCommand.getType() == CtlCommand.CtlCommandChoices.add){
                CtlEntry ctlEntry = ctlCommand.getCtlEntry();
                if(ctlEntry.getType() == type){
                    EtsiTs103097Certificate caCertificate = getCertificateFromCtlEntry(ctlEntry);
                    if(caCertificate != null && caCertificate.getToBeSigned().getId().equals(certificateId)){
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
    private CtlFormat getCtlFormat(EtsiTs102941CTL etsiTs102941CTL) throws IOException{
        Ieee1609Dot2Data innerData = ((SignedData) etsiTs102941CTL.getContent().getValue()).getTbsData().getPayload().getData();
        Opaque opaque = (Opaque) innerData.getContent().getValue();
        EtsiTs102941Data toBeSignedCtl = new EtsiTs102941Data(opaque.getData());
        if(toBeSignedCtl.getContent().getType() == certificateTrustListRca){
            return toBeSignedCtl.getContent().getToBeSignedRcaCtl();
        }
        if(toBeSignedCtl.getContent().getType() == certificateTrustListTlm){
            return toBeSignedCtl.getContent().getToBeSignedTlmCtl();
        }
        return null;
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

}
