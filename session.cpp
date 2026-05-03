#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            Utils::secureCleanMemory((BYTE*)_privateKeyPassword, strlen(_privateKeyPassword));
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}


bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort) 
{
        memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
        _remoteAddress.sin_family = AF_INET;
        _remoteAddress.sin_port = htons(remotePort);
        _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter =_outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}


void Session::cleanDhData()
{
    // ...
	// 1. Clean the mbedtls Diffie-Hellman context and free its allocated memory using the CryptoWrapper.
	// This prevents memory leaks and ensures the internal state of the DH object is securely cleared.
	if (_dhContext != NULL)
	{
		CryptoWrapper::cleanDhContext(&_dhContext);
	}

	// 2. Securely zero out the buffers that stored the local public key, the remote public key, and the shared secret.
	// This is important to ensure no sensitive material remains in memory after the session is closed.
	Utils::secureCleanMemory(_localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
	Utils::secureCleanMemory(_remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
	Utils::secureCleanMemory(_sharedDhSecretBuffer, DH_KEY_SIZE_BYTES);

}


void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }
    
    // ...
	// 3. Derive a session-specific MAC key from the shared Diffie-Hellman secret material.
	// We use HKDF-SHA256 (HMAC-based Key Derivation Function) to derive a cryptographically strong key.
	// The context string includes the session ID to ensure the key is unique to this specific session context.
	if (!CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES, 
                                             (const BYTE*)keyDerivationContext, (size_t)strlen(keyDerivationContext), 
                                             macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES))
	{
		printf("Error deriving MAC key\n");
		exit(0);
	}
}


void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        exit(0);
    }
    
    // ...
	// 4. Derive the main session encryption key from the shared Diffie-Hellman secret material.
	// This key is used for protecting the data channel (AES-GCM encryption/decryption).
	// We use HKDF-SHA256 (HMAC-based Key Derivation Function) with a unique context string 
	// to ensure domain separation from the MAC key derived earlier.
	if (!CryptoWrapper::deriveKey_HKDF_SHA256(NULL, 0, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES, 
                                             (const BYTE*)keyDerivationContext, (size_t)strlen(keyDerivationContext), 
                                             _sessionKey, SYMMETRIC_KEY_SIZE_BYTES))
	{
		printf("Error deriving Session key\n");
		exit(0);
	}
}


ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    // we will be building the following message parts:
    // 1: my DH public key 
    // 2: My certificate (PEM)
    // 3: Signature over concatenated public keys with my permanenet private key
    // 4: MAC over my certificate with the shared MAC key

    // get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareDhMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }

    // get my private key for signing
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareDhMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (conacatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }
    BYTE signature[SIGNATURE_SIZE_BYTES];
    // ...
	// 1. Sign the concatenated public keys (Local PK || Remote PK).
	// This proves ownership of the private key associated with the certificate and binds the exchange.
	if (!CryptoWrapper::signMessageRsa3072Pss(conacatenatedPublicKeysSmartPtr, conacatenatedPublicKeysSmartPtr.size(), 
                                              privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
	{
		printf("prepareDhMessage #%d failed - Error signing public keys\n", messageType);
		CryptoWrapper::cleanKeyContext(&privateKeyContext);
		cleanDhData();
		return NULL;
	}

	// We no longer need the private key context.
	CryptoWrapper::cleanKeyContext(&privateKeyContext);

    // Now we will calculate the MAC over my certiicate
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    // ...
	// 2. Derive the session-specific MAC key and calculate the HMAC over our certificate.
	// This binds our identity (the certificate) to the shared secret established by the DH exchange.
	BYTE macKey[SYMMETRIC_KEY_SIZE_BYTES];
	deriveMacKey(macKey);

	if (!CryptoWrapper::hmac_SHA256(macKey, SYMMETRIC_KEY_SIZE_BYTES, certBufferSmartPtr, certBufferSmartPtr.size(), 
                                   calculatedMac, HMAC_SIZE_BYTES))
	{
		printf("prepareDhMessage #%d failed - Error calculating HMAC\n", messageType);
		Utils::secureCleanMemory(macKey, SYMMETRIC_KEY_SIZE_BYTES);
		cleanDhData();
		return NULL;
	}

	// Securely clear the temporary MAC key from the stack.
	Utils::secureCleanMemory(macKey, SYMMETRIC_KEY_SIZE_BYTES);

    // pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
    return messageToSend;
}

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    unsigned int expectedNumberOfParts = 4;
    unsigned int partIndex = 0;

    // We are expecting 4 parts
    // 1: Remote public DH key (in message type 3 we will check that it equalss the value received in message type 1)
    // 2: Remote certificate (PEM) null terminated
    // 3: Signature over concatenated public keys (remote|local)
    // 4: MAC over remote certificate with the shared MAC key

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    // Load root CA certificate for verification
    ByteSmartPtr rootCaSmartPtr = Utils::readBufferFromFile(_rootCaCertFilename);
    if (rootCaSmartPtr == NULL) {
        printf("verifySigmaMessage #%d failed - Error reading Root CA certificate\n", messageType);
        return false;
    }

    // we will now verify if the received certificate belongs to the expected remote entity
    // ...
	// 1. Verify the remote certificate chain against our Root CA and check the expected identity (CN).
    // This step ensures the certificate is authentic, trusted, and belongs to the entity we intend to talk to.
	if (!CryptoWrapper::checkCertificate(rootCaSmartPtr, rootCaSmartPtr.size(), parts[1].part, parts[1].partSize, _expectedRemoteIdentityString))
	{
		printf("verifySigmaMessage #%d failed - Certificate verification failed\n", messageType);
		return false;
	}

	// Extract the public key from the validated certificate for signature verification.
	KeypairContext* peerPublicKeyContext = NULL;
	if (!CryptoWrapper::getPublicKeyFromCertificate(parts[1].part, parts[1].partSize, &peerPublicKeyContext))
	{
		printf("verifySigmaMessage #%d failed - Error getting public key from certificate\n", messageType);
		return false;
	}

    // now we will verify if the signature over the concatenated public keys is ok
    // ...
	// 2. Concatenate the public keys (Remote PK || Local PK) and verify the signature.
	// Binding the public keys into the signature prevents "Man-in-the-Middle" attacks by ensuring 
    // both parties are signing the exact same key exchange data.
	ByteSmartPtr concatenatedPublicKeys = concat(2, parts[0].part, DH_KEY_SIZE_BYTES, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
	bool sigResult = false;
	if (!CryptoWrapper::verifyMessageRsa3072Pss(concatenatedPublicKeys, concatenatedPublicKeys.size(), peerPublicKeyContext, parts[2].part, parts[2].partSize, &sigResult) || !sigResult)
	{
		printf("verifySigmaMessage #%d failed - Signature verification failed\n", messageType);
		CryptoWrapper::cleanKeyContext(&peerPublicKeyContext);
		return false;
	}
	CryptoWrapper::cleanKeyContext(&peerPublicKeyContext);

    if (messageType == 2)
    {
        // Now we will calculate the shared secret
        // ...
		// 3. For the client (Message #2), we now have the peer's verified public key and can compute the shared secret.
        // We store their public key and then use the DH context to derive the master shared secret.
		memcpy_s(_remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, parts[0].part, parts[0].partSize);
		if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
		{
			printf("verifySigmaMessage #%d failed - Error calculating shared secret\n", messageType);
			return false;
		}
    }

    // Now we will verify the MAC over the certificate
    // ...
	// 4. Finally, derive the MAC key and verify the HMAC over the peer's certificate.
	// This final step proves that the peer actually knows the shared secret, completing the mutual authentication.
	BYTE macKey[SYMMETRIC_KEY_SIZE_BYTES];
	BYTE calculatedMac[HMAC_SIZE_BYTES];
	deriveMacKey(macKey);

	if (!CryptoWrapper::hmac_SHA256(macKey, SYMMETRIC_KEY_SIZE_BYTES, parts[1].part, parts[1].partSize, calculatedMac, HMAC_SIZE_BYTES))
	{
		printf("verifySigmaMessage #%d failed - Error calculating HMAC\n", messageType);
		Utils::secureCleanMemory(macKey, SYMMETRIC_KEY_SIZE_BYTES);
		return false;
	}
	Utils::secureCleanMemory(macKey, SYMMETRIC_KEY_SIZE_BYTES);

	if (memcmp(calculatedMac, parts[3].part, HMAC_SIZE_BYTES) != 0)
	{
		printf("verifySigmaMessage #%d failed - HMAC mismatch\n", messageType);
		return false;
	}

	return true;
}


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{
    // mine
    /*
    // we will do a plain copy for now
    size_t encryptedMessageSize = messageSize;
    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(encryptedMessageSize);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    memcpy_s(ciphertext, encryptedMessageSize, message, messageSize);

    ByteSmartPtr result(ciphertext, encryptedMessageSize);
    return result;
    */

	// 1. Calculate the required size for the ciphertext.
	// In AES-GCM, the output includes the encrypted payload plus the IV and the authentication tag (MAC).
	size_t ciphertextSize = CryptoWrapper::getCiphertextSizeAES_GCM256(messageSize);
	BYTE* ciphertextBuffer = (BYTE*)Utils::allocateBuffer(ciphertextSize);
	if (ciphertextBuffer == NULL)
	{
		return NULL;
	}

	// 2. Prepare the MessageHeader to be used as Additional Authenticated Data (AAD).
	// We include the header in the GCM authentication process to ensure the message type,
	// session ID, and message counter cannot be modified by an attacker.
	MessageHeader aadHeader;
	prepareMessageHeader(&aadHeader, messageType, ciphertextSize);

	// 3. Encrypt the plaintext using the established session key.
	// The CryptoWrapper handles the internal generation of a random IV and appends the MAC tag.
	size_t actualCiphertextSize = 0;
	if (!CryptoWrapper::encryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, message, messageSize, 
                                          (const BYTE*)&aadHeader, sizeof(MessageHeader), 
                                          ciphertextBuffer, ciphertextSize, &actualCiphertextSize))
	{
		printf("prepareEncryptedMessage failed - AES-GCM encryption error\n");
		Utils::freeBuffer(ciphertextBuffer);
		return NULL;
	}

	return ByteSmartPtr(ciphertextBuffer, actualCiphertextSize);
}


bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    // mine
    /*
    // we will do a plain copy for now
    size_t ciphertextSize = header->payloadSize;
    size_t plaintextSize = ciphertextSize;
    

    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = plaintextSize;
    }

    return true;
    */

	// 1. Calculate the expected size of the plaintext.
	// AES-GCM plaintext is smaller than the ciphertext because the IV and MAC tag are removed.
	size_t ciphertextSize = header->payloadSize;
	size_t plaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);
	
	// 2. Allocate a temporary buffer for the decryption process.
	// We decrypt into a temporary buffer first to ensure we don't overwrite the ciphertext 
    // until the authentication (MAC check) is successful.
	BYTE* plaintextBuffer = (BYTE*)Utils::allocateBuffer(plaintextSize);
	if (plaintextBuffer == NULL)
	{
		return false;
	}

	// 3. Decrypt and verify the authentication tag using the session key.
	// The MessageHeader is provided as Additional Authenticated Data (AAD) to verify its integrity.
	size_t actualPlaintextSize = 0;
	if (!CryptoWrapper::decryptAES_GCM256(_sessionKey, SYMMETRIC_KEY_SIZE_BYTES, buffer, ciphertextSize, 
                                          (const BYTE*)header, sizeof(MessageHeader), 
                                          plaintextBuffer, plaintextSize, &actualPlaintextSize))
	{
		printf("decryptMessage failed - AES-GCM decryption/authentication error\n");
		Utils::freeBuffer(plaintextBuffer);
		return false;
	}

	// 4. On successful decryption and authentication, copy the plaintext back to the original message buffer.
	// We also update the payload size in the header to reflect the decrypted data length.
	memcpy_s(buffer, ciphertextSize, plaintextBuffer, actualPlaintextSize);
	header->payloadSize = (unsigned int)actualPlaintextSize;
	if (pPlaintextSize != NULL)
	{
		*pPlaintextSize = actualPlaintextSize;
	}

	Utils::freeBuffer(plaintextBuffer);
	return true;
}


bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}















