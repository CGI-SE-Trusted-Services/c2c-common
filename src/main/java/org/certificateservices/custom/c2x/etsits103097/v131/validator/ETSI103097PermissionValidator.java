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
package org.certificateservices.custom.c2x.etsits103097.v131.validator;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.common.validator.BaseCertificateValidator;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.DefaultSSPLookup;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.EmptyDefaultSSPLookup;

import java.util.List;

/**
 * Permission validator for evaluating app and cert issue permissions of ETSI 103 097 Certificates.
 * <p>
 *     It also contains extra method to check specific permissions for the SecuredCertificateRequestService (623)
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSI103097PermissionValidator extends BasePermissionValidator {

    /**
     * Constructor used for validators in a PKI with no known default SSP values. Initializes
     * itself with an EmptyDefaultSSPLookup.
     */
    public ETSI103097PermissionValidator(){
        super(new EmptyDefaultSSPLookup());
    }

    /**
     * Constructor used in PKIs with known default SSP values used when PSIDSSP contains empty SSP data.
     *
     * @param defaultSSPLookup lookup implementation of default SSP values for specific SSP and SSPRanges.
     */
    public ETSI103097PermissionValidator(DefaultSSPLookup defaultSSPLookup){
        super(defaultSSPLookup);
    }

    /**
     * Method to validate permissions in a certificate chain that starts with an end entity certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param certificateChain the certificate chain with end entity certificate first.
     * @throws IllegalArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    @Override
    public void checkPermissions(EndEntityType targetEndEntityType, Certificate[] certificateChain) throws IllegalArgumentException, InvalidCertificateException {
        checkPermissions(targetEndEntityType,0,certificateChain);
    }

    /**
     * Special use-case method to validate permissions in a certificate chain that starts with a ca certificate. It will check
     * all permissions set in the certificate for the given end entity type.
     *
     * @param targetEndEntityType the target end entity type to validate.
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain with end entity certificate first.
     * @throws IllegalArgumentException if one of the specified parameters was invalid.
     * @throws InvalidCertificateException if certificate chain contained invalid permissions.
     */
    @Override
    public void checkPermissions(EndEntityType targetEndEntityType, int chainLengthIndex, Certificate[] certificateChain) throws IllegalArgumentException, InvalidCertificateException {
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);

        if(ieee160CertChain.length > 1){
            for(int i=0;i<(ieee160CertChain.length-1);i++){
                checkPermissions(targetEndEntityType,i + chainLengthIndex,ieee160CertChain[i], ieee160CertChain[i+1]);
            }
        }
    }

    /**
     * Method to check if the first certificate in supplied chain have a specific appPermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param certificateChain the certificate chain to check permission, only the first certificate that have its certificate checked.
     * @throws InvalidCertificateException if given permission wasn't found in the certificate.
     */
    public void checkCertServicePermissionInAppPermissions(byte ssPVersion, byte ssPPermissions, Certificate[] certificateChain) throws InvalidCertificateException{
        byte[] sspData = new byte[]{ssPVersion,ssPPermissions};
        if(certificateChain.length == 0){
            throw new InvalidCertificateException("Unable to check permissions for empty chain.");
        }
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);

        List<PsidSsp> servicePermissions = filterPsidSspByPSID(AvailableITSAID.SecuredCertificateRequestService.getValueAsLong(),ieee160CertChain[0].getToBeSigned().getAppPermissions());
        for(PsidSsp servicePermission : servicePermissions){
            if(servicePermission.getSSP().getType() == ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp){
                byte[] bitmapSpp = servicePermission.getSSP().getBitmapSsp().getData();
                if(sspData.length != bitmapSpp.length){
                    throw new InvalidCertificateException("Invalid service permission for SecuredCertificateRequestService (623), provided SSPValue length doesn't match bitmap length in appPermissions.");
                }
                boolean foundMatch = true;
                for(int i=0; i < bitmapSpp.length; i++){
                    if((sspData[i] & bitmapSpp[i]) != sspData[i]){
                        foundMatch = false;
                        break;
                    }
                }
                if(foundMatch){
                   return;
                }
            }else{
                throw new InvalidCertificateException("Invalid service permission for SecuredCertificateRequestService (623), expected type bitmapSsp but the certificate contained opaque.");
            }
        }
        throw new InvalidCertificateException("Couldn't find permission for SecuredCertificateRequestService (623): " + Hex.toHexString(sspData) + " in certificate.");
    }


    /**
     * Method to check if the first certificate in supplied chain have a specific certIssuePermission set in
     * its SecuredCertificateRequestService (623) SSP Data.
     *
     * @param ssPVersion the version byte of the SSP Data (Use SecuredCertificateRequestServicePermissions.VERSION_ constants)
     * @param ssPPermissions the permission to look up in the SSP Data (Use SecuredCertificateRequestServicePermission constants)
     * @param endEntityType the end entity type to lookup
     * @param chainLengthIndex index parameter send to retrieve the correct group permissions from certificate. If validating chain that starts with end
     *                         entity certificate should chainLengthIndex be 0, if certificate chain starts with issuer of end entity certificate it should
     *                         be 1 and so on incremented up to root certificate in chain.
     * @param certificateChain the certificate chain to lookup cert issuer permissions if the first certificate.
     * @throws InvalidCertificateException if no given permissions was found in certificate.
     */
    public void checkCertServicePermissionInIssuePermissions(byte ssPVersion, byte ssPPermissions, EndEntityType endEntityType, int chainLengthIndex, Certificate[] certificateChain) throws InvalidCertificateException{
        byte[] sspData = new byte[]{ssPVersion,ssPPermissions};
        if(certificateChain.length == 0){
            throw new InvalidCertificateException("Unable to check permissions for empty chain.");
        }
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] ieee160CertChain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);

        List<PsidGroupPermissions> applicablePsIdGroupPermissions = filterByEndEntityTypeAndChainLength(endEntityType, chainLengthIndex, ieee160CertChain[0].getToBeSigned().getCertIssuePermissions().getSequenceValues());
        long pSId = AvailableITSAID.SecuredCertificateRequestService.getValueAsLong();
        List<PsidSspRange> filteredPsidSspRange = filterPsidSspRangeByPSID(pSId,applicablePsIdGroupPermissions);

        try {
            checkBitmapSSP(pSId, new BitmapSsp(sspData), filteredPsidSspRange);
        }catch(InvalidCertificateException e){
            throw new InvalidCertificateException("Couldn't find issue permission for SecuredCertificateRequestService (623): " + Hex.toHexString(sspData) + " in certificate.");
        }
    }

    /**
     * Help method to check app and cert issue permission of an certificate against permissions in its issuer.
     * If certificate contains certRequestPermissions is InvalidCertificateException thrown since it is not
     * supported in ETSI 103097 PKIs.
     * @param endEntityType the end entity type to evaluate permissions for.
     * @param chainLength the current index in the chain evaulation, starts at 0 and is incremented.
     * @param certificate the certificate to check permissions for towards it issuer
     * @param issuer the issuer certificate.
     * @throws IllegalArgumentException if one of the parameter contained invalid data.
     * @throws InvalidCertificateException if certificate contained invalid permissions.
     */
    protected void checkPermissions(EndEntityType endEntityType, int chainLength, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate issuer) throws IllegalArgumentException, InvalidCertificateException{
        checkAppPermissions(endEntityType,chainLength,certificate,issuer);
        checkCertIssuePermissions(endEntityType,chainLength,certificate,issuer);

        if(certificate.getToBeSigned().getCertRequestPermissions() != null){
            throw new InvalidCertificateException("Invalid certiifcate, certRequestPermissions is currently not supported during validation.");
        }
    }


}
