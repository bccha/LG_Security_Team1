# LG_Security_Team1

[Server Requirements](Server.md)

## Requirement
1. The ability for the **user to register with the system**. This specific requirement has the following subcomponents.
    1. The user shall provide the system their email address and password. 
The **system shall ensure that the user’s password is secure**.
Passwords must be a **minimum of 10 characters long and include one number and one symbol**.
    1. The system shall use **two-factor authentication**.
    1. The system should force a user to **periodically reset their password (at least once a month)**.
    1. If the user enters the **incorrect** password more than **three times**, then their account will be **locked for one hour**.
    1. The system shall **allow users to change their email address in a secure way**.
    1. The system shall provide the ability for the user to **recover or change their password in the event it is lost**.

1. After successful registration the system shall **assign the user a unique contact identification name** (contact identifier) ; 
this can be the **user’s email address or some other name chosen by the user** if it does **not conflict** with other user’s contact identifiers already in the system.

1. The system shall provide a **contact list that associates a person** with their contact identifier (last name, first name, address, e-mail, contact identifier). 
When a contact is associated with a contact identifier the VoIP application shall **display the contact’s name instead of the contact identifier**.

1. The system shall provide the ability to **initiate a call using a contact identifier or the contacts list**. 
During the call initiation, the user shall be **presented with call status and outcome** (answered, busy or rejected). 
During call initiation the user shall have the **ability to end the call at any time**.

1. The system shall provide the **ability to accept or reject calls while not in a call**. 
Application shall **show the caller’s contact identifier or contact name** during an incoming call.

1. The system shall **notify the user of missed calls**, 
either because the call was **not accepted** (거절)
or because the called entity **was in another call**.(통화중)

1. Provide the ability to **terminate a call at any time** while in a call. 
If a call is terminated by one user, **the other caller shall be notified**.

1. **Application** shall be **brought to the foreground** during an incoming call.

1. This application is a **point-to-point communication system**. 
That is, each end point of the call should function as both a server and a client.
