# Java Implementation of ITS Intelligent Transport Systems (ITS) Security Security header and certificate formats
# ETSI TS 103 097 V1.1.1

This is a library used to generate data structures from the ETSI TS 103 097 specification.

It supports generation of the following data structures will all related substructures:
  - Root CA Certificate
  - Enrollment CA Certificate
  - Authorization CA Certificate
  - Enrollment Credential Certificate
  - Authorization Ticket
  - Secure Messages for CAM and DENM

Encryption of generated Secure Messages is not implemented in the current version. 

See Javadoc adn examples below for more detailed information.

_Important_: In the current version there have been no proper interoperability testing of the signature of neither certificates or message data. The implementation has been done from the specification and no real data structures from another implementation have been available. 

# License
The software is released under AGPL, see LICENSE.txt for more details. In order to get the software under a different licensing agreement please contact p.vendil (at) cgi.com

# Example Code


