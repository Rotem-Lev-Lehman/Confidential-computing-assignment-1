#include <stdio.h>
#include <cstring>
#include "client_session.h"



ClientSession::ClientSession(unsigned int remotePort, const char* remoteIpAddress, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity):Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    if (!active())
    {
        return;
    }

    setRemoteAddress(remoteIpAddress, remotePort);

   // initialize x, p, g
    if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // sending unencrypted message to initiate connection
    // this message contains the dh public key g^x
    if (!sendMessageInternal(HELLO_SESSION_MESSAGE, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES)) {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
    _state = HELLO_SESSION_MESSAGE;

    BYTE messageBuffer[MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', MESSAGE_BUFFER_SIZE_BYTES);

    BYTE* pPayload = NULL; // points to the place inside the messageBuffer that has the actual data (without the headers)
    size_t payloadSize = 0;

    /* this is where we recevie SIGMA message 2 - you can see the code that prepares the message in Session::prepareSigmaMessage 
    response contains: servers DH public key, 
                            servers certificate, 
                            a digital signature (of the DH public keys concatenated: ServerPK||ClientPK)
                            MAC (of the servers certificate, using a key derived from the shared secret g^xy) */
    Session::ReceiveResult rcvResult = receiveMessage(messageBuffer, MESSAGE_BUFFER_SIZE_BYTES, 10, &pPayload, &payloadSize);

    if (rcvResult != RR_PROTOCOL_MESSAGE || _state != HELLO_BACK_SESSION_MESSAGE)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // here we need to verify the DH message 2 part

    /* check server crt: check that the servers crt is signed by the root ca
                            check that the certificates name matches peerIdentity

    verify the servers RSA singature of the DH public keys

    calculate the shared secret g^xy

    verify that the servers crt wasnt tampered:
                derive a mac key using the shared secret and calculate mac of servers crt using mackey, then compare to what the server sent (should match)*/
    if (!verifySigmaMessage(2, pPayload, (size_t)payloadSize))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // send SIGMA message 3 part
    /* just like message 2 the server sent but opposite.
        The digital signature is of ClientPK||ServerPK
    */
	ByteSmartPtr message3 = prepareSigmaMessage(3);
    if (message3 == NULL)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    if (!sendMessageInternal(HELLO_DONE_SESSION_MESSAGE, message3, message3.size()))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // now we will calculate the session key
    // AES-GCM encryption keys
    deriveSessionKey();

    _state = DATA_SESSION_MESSAGE;
    return;
}


ClientSession::~ClientSession()
{
    closeSession();
    destroySession();
}


Session::ReceiveResult ClientSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize)
{
    if (!active())
    {
        return RR_FATAL_ERROR;
    }

    struct sockaddr_in remoteAddr;
    int remoteAddrSize = sizeof(remoteAddr);
    memset(&remoteAddr, 0, remoteAddrSize);

    size_t recvSize = 0;
    Socket::ReceiveResult rcvResult = _localSocket->receive(buffer, bufferSize, timeout_sec, &recvSize, &remoteAddr);
    switch (rcvResult)
    {
    case Socket::RR_TIMEOUT:
        return RR_TIMEOUT;
    case Socket::RR_ERROR:
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;
    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    if (header->messageCounter != _incomingMessageCounter)
    {
        return RR_BAD_MESSAGE;
    }

    _incomingMessageCounter++;

    switch (header->messageType)
    {
    case GOODBYE_SESSION_MESSAGE:
        return RR_SESSION_CLOSED;
    case HELLO_SESSION_MESSAGE:
        return RR_BAD_MESSAGE;
    case HELLO_BACK_SESSION_MESSAGE: //this is where we receive SIGMA message 2
        if (_state == HELLO_SESSION_MESSAGE)
        {
            _sessionId = header->sessionId;
            _state = HELLO_BACK_SESSION_MESSAGE;

            if (ppPayload != NULL)
                *ppPayload = buffer + sizeof(MessageHeader);

            if (pPayloadSize != NULL)
                *pPayloadSize = header->payloadSize;

            printf("Session started with %s\n", _expectedRemoteIdentityString);
            return RR_PROTOCOL_MESSAGE;
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    case DATA_SESSION_MESSAGE:
        if (_state == DATA_SESSION_MESSAGE)
        {
            size_t plaintextSize = 0;
            if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
            {
                return RR_BAD_MESSAGE;
            }

            if (ppPayload != NULL)
            {
                *ppPayload = buffer + sizeof(MessageHeader);
            }

            if (pPayloadSize != NULL)
            {
                *pPayloadSize = plaintextSize;
            }
            _state = DATA_SESSION_MESSAGE;
            return RR_DATA_MESSAGE;
        }
        else
            return RR_BAD_MESSAGE;
    }

    return RR_BAD_MESSAGE;
}