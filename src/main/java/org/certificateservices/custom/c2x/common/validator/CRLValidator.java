package org.certificateservices.custom.c2x.common.validator;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

/**
 * Interface for a CRL Validator verifying that the CRL itself is valid and that a given
 * certificate is not included in the list.
 *
 * @author Philip Vendil 2020-02-04
 */
public interface CRLValidator {

    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * <p>
     *     <i>Important</i>The method will only verify the CRL and to the specified certificate,
     *     it should be validated separately.
     * </p>
     * <p>
     *     The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     *
     *
     * For each CRL in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CRL validity</li>
     *     <li>Issuing Certificate has permissions to issue CRLs</li>
     *     <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificate the certificate to check if revoked. If null is revocation not checked.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    void verifyAndValidate(EtsiTs102941CRL crl, Certificate certificate, Date checkDate,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain)
            throws IllegalArgumentException, InvalidCRLException, InvalidCertificateException, NoSuchAlgorithmException, CertificateRevokedException;


    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * <p>
     *     <i>Important</i>The method will only verify the CRL and to the specified certificate,
     *     it should be validated separately.
     * </p>
     * <p>
     *     The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     *
     *
     * For each CRL in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CRL validity</li>
     *     <li>Issuing Certificate has permissions to issue CRLs</li>
     *     <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificateId the certificate id to check if revoked. If null is revocation not checked.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only CRL.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     * @throws CertificateRevokedException if related certificate was revoked.
     */
    void verifyAndValidate(EtsiTs102941CRL crl, HashedId8 certificateId, Date checkDate,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain)
            throws IllegalArgumentException, InvalidCRLException, InvalidCertificateException, NoSuchAlgorithmException, CertificateRevokedException;

    /**
     * Method that verifies and validates a CRL and checks if related certificate id is revoked.
     * This method have support for a intermediate CAs between rootca and EA and AA.
     * <p>
     *     <i>Important</i>The method will only verify the CRL and to the specified certificate,
     *     it should be validated separately.
     * </p>
     * <p>
     *     The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     *
     *
     * For each CRL in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CRL validity</li>
     *     <li>Issuing Certificate has permissions to issue CRLs</li>
     *     <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificateId the certificate id to check if revoked. If null is revocation not checked.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     @throws CertificateRevokedException if related certificate was revoked.
     */
    void verifyAndValidate(EtsiTs102941CRL crl, HashedId8 certificateId, Date checkDate,
                           Map<HashedId8, Certificate> certStore,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain)
            throws IllegalArgumentException, InvalidCRLException, InvalidCertificateException,
            NoSuchAlgorithmException, CertificateRevokedException;

    /**
     * Method that verifies and validates a CRL and checks if related certificate is revoked.
     * This method have support for a intermediate CAs between rootca and EA and AA.
     * <p>
     *     <i>Important</i>The method will only verify the CRL and to the specified certificate,
     *     it should be validated separately.
     * </p>
     * <p>
     *     The method will build a chain for the CRL from the set of trust anchors.
     * </p>
     *
     *
     * For each CRL in the built chain it will check.
     * <ul>
     *     <li>Signature verifies</li>
     *     <li>CRL validity</li>
     *     <li>Issuing Certificate has permissions to issue CRLs</li>
     *     <li>That specified certificate isn't included.</li>
     * </ul>
     * <p>
     *   <b>Permissions is only checked that it is consistent upwards in the chain. It does not check a specific permission</b>
     * </p>
     *
     * @param crl the CRL to verify, validate and check if specified certificate is revoked.
     * @param certificate the certificate to check if revoked. If null is revocation not checked.
     * @param checkDate the date to check validity of CRL and its certificate chain against.
     * @param certStore a certstore that contains all intermediate CA certificates that is needed to build the chain.
     * @param trustStore a certstore of root ca certificates that are trusted.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws IllegalArgumentException if one of the parameters where invalid.
     * @throws InvalidCRLException if CRL was not verifyable or not within time constraints.
     * @throws InvalidCertificateException if one of the certificate in the build certificate chain was invalid.
     * @throws NoSuchAlgorithmException if use hash algorithm isn't supported by the system.
     @throws CertificateRevokedException if related certificate was revoked.
     */
    void verifyAndValidate(EtsiTs102941CRL crl, Certificate certificate, Date checkDate,
                           Map<HashedId8, Certificate> certStore,
                           Map<HashedId8, Certificate> trustStore, boolean entireChain)
            throws IllegalArgumentException, InvalidCRLException, InvalidCertificateException,
            NoSuchAlgorithmException, CertificateRevokedException;
}
