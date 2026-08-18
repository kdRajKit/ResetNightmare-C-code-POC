/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        kerberos.c                                                                                           *
*   DESCRIPCION:   Transporte KDC, preautenticacion y gestion de credenciales Kerberos.                                *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                            IMPLEMENTACION KERBEROS                                                   *
***********************************************************************************************************************/

static BOOL sendAll( SOCKET hSocket, const VOID *pvData, INT cbData, PINT piSocketError )
{
	const CHAR *pcData = ( const CHAR * )pvData;
	INT         cbSent = 0;

	if ( !piSocketError )
		return FALSE;
	*piSocketError = 0;
	if ( hSocket == INVALID_SOCKET || !pvData || cbData <= 0 )
		return FALSE;
	while ( cbSent < cbData )
	{
		INT cbCurrent = send( hSocket, pcData + cbSent, cbData - cbSent, 0 );
		if ( cbCurrent == SOCKET_ERROR )
		{
			*piSocketError = WSAGetLastError();
			return FALSE;
		}
		if ( cbCurrent == 0 )
			return FALSE;
		cbSent += cbCurrent;
	}
	return TRUE;
}

static BOOL receiveAll( SOCKET hSocket, PVOID pvData, INT cbData, PINT piSocketError )
{
	PCHAR pcData     = ( PCHAR )pvData;
	INT   cbReceived = 0;

	if ( !piSocketError )
		return FALSE;
	*piSocketError = 0;
	if ( hSocket == INVALID_SOCKET || !pvData || cbData <= 0 )
		return FALSE;
	while ( cbReceived < cbData )
	{
		INT cbCurrent = recv( hSocket, pcData + cbReceived, cbData - cbReceived, 0 );
		if ( cbCurrent == SOCKET_ERROR )
		{
			*piSocketError = WSAGetLastError();
			return FALSE;
		}
		if ( cbCurrent == 0 )
			return FALSE;
		cbReceived += cbCurrent;
	}
	return TRUE;
}

BOOL sendKerberosRequest( PCSTR pszServer, PCSTR pszPort, const VOID *pvContent, INT cbContent, PBYTE *ppbResponse,
                          PINT pcbResponse )
{
	WSADATA          stWsaData;
	struct addrinfo  stHints    = { 0 };
	struct addrinfo *pAddresses = NULL;
	struct addrinfo *pAddress;
	SOCKET           hSocket = INVALID_SOCKET;
	ULONG            cbNetworkValue;
	BOOL             bWsaStarted     = FALSE;
	BOOL             bSuccess        = FALSE;
	DWORD            dwTimeout       = KRB_SOCKET_TIMEOUT_MS;
	PCSTR            pszFailureStage = NULL;
	INT              iFailureCode    = 0;
	INT              iAddressFamily  = AF_INET;
	INT              iResult;

	if ( !ppbResponse || !pcbResponse )
		return FALSE;
	*ppbResponse = NULL;
	*pcbResponse = 0;
	if ( !pszServer || !pszPort || !pvContent || cbContent <= 0 )
		return FALSE;

	iResult = WSAStartup( MAKEWORD( 2, 2 ), &stWsaData );
	if ( iResult != 0 )
	{
		printf( "[-] TCP %s:%s fallo en WSAStartup (codigo %d).\n", pszServer, pszPort, iResult );
		return FALSE;
	}
	bWsaStarted         = TRUE;
	stHints.ai_family   = AF_INET;
	stHints.ai_socktype = SOCK_STREAM;
	stHints.ai_protocol = IPPROTO_TCP;
	iResult             = getaddrinfo( pszServer, pszPort, &stHints, &pAddresses );
	if ( iResult != 0 )
	{
		pszFailureStage = "resolucion";
		iFailureCode    = iResult;
		goto Cleanup;
	}

	for ( pAddress = pAddresses; pAddress; pAddress = pAddress->ai_next )
	{
		if ( pAddress->ai_addrlen > INT_MAX )
			continue;
		iAddressFamily = pAddress->ai_family;
		hSocket        = socket( pAddress->ai_family, pAddress->ai_socktype, pAddress->ai_protocol );
		if ( hSocket == INVALID_SOCKET )
		{
			pszFailureStage = "creacion del socket";
			iFailureCode    = WSAGetLastError();
			continue;
		}
		if ( setsockopt( hSocket, SOL_SOCKET, SO_SNDTIMEO, ( PCSTR )&dwTimeout, ( INT )sizeof( dwTimeout ) ) ==
		         SOCKET_ERROR ||
		     setsockopt( hSocket, SOL_SOCKET, SO_RCVTIMEO, ( PCSTR )&dwTimeout, ( INT )sizeof( dwTimeout ) ) ==
		         SOCKET_ERROR )
		{
			pszFailureStage = "configuracion del socket";
			iFailureCode    = WSAGetLastError();
			closesocket( hSocket );
			hSocket = INVALID_SOCKET;
			continue;
		}
		if ( connect( hSocket, pAddress->ai_addr, ( INT )pAddress->ai_addrlen ) == 0 )
		{
			pszFailureStage = NULL;
			iFailureCode    = 0;
			break;
		}
		pszFailureStage = "conexion";
		iFailureCode    = WSAGetLastError();
		closesocket( hSocket );
		hSocket = INVALID_SOCKET;
	}
	if ( hSocket == INVALID_SOCKET )
		goto Cleanup;

	cbNetworkValue = htonl( ( ULONG )cbContent );
	if ( !sendAll( hSocket, &cbNetworkValue, sizeof( cbNetworkValue ), &iFailureCode ) )
	{
		pszFailureStage = "envio de longitud";
		goto Cleanup;
	}
	if ( !sendAll( hSocket, pvContent, cbContent, &iFailureCode ) )
	{
		pszFailureStage = "envio de solicitud";
		goto Cleanup;
	}
	if ( !receiveAll( hSocket, &cbNetworkValue, sizeof( cbNetworkValue ), &iFailureCode ) )
	{
		pszFailureStage = "recepcion de longitud";
		goto Cleanup;
	}

	cbNetworkValue = ntohl( cbNetworkValue );
	if ( cbNetworkValue == 0 || cbNetworkValue > KRB_MAX_TCP_RESPONSE )
	{
		printf( "[-] TCP %s:%s devolvio una longitud no valida: %lu.\n", pszServer, pszPort,
		        ( unsigned long )cbNetworkValue );
		goto Cleanup;
	}
	*pcbResponse = ( INT )cbNetworkValue;
	*ppbResponse = memAlloc( ( SIZE_T )*pcbResponse );
	if ( !*ppbResponse )
	{
		printf( "[-] TCP %s:%s no pudo reservar %d bytes para la respuesta.\n", pszServer, pszPort, *pcbResponse );
		goto Cleanup;
	}
	if ( !receiveAll( hSocket, *ppbResponse, *pcbResponse, &iFailureCode ) )
	{
		pszFailureStage = "recepcion de respuesta";
		goto Cleanup;
	}
	bSuccess = TRUE;

Cleanup:
	if ( !bSuccess )
	{
		if ( pszFailureStage )
			printf( "[-] TCP %s:%s fallo en %s (familia %d, codigo %d).\n", pszServer, pszPort, pszFailureStage,
			        iAddressFamily, iFailureCode );
		if ( *ppbResponse )
			VirtualFree( *ppbResponse, 0, MEM_RELEASE );
		*ppbResponse = NULL;
		*pcbResponse = 0;
	}
	if ( hSocket != INVALID_SOCKET )
		closesocket( hSocket );
	if ( pAddresses )
		freeaddrinfo( pAddresses );
	if ( bWsaStarted )
		WSACleanup();
	return bSuccess;
}

static VOID releaseKerberosTicket( KERBEROS_TICKET *pTicket )
{
	if ( !pTicket )
		return;
	if ( pTicket->pszRealm )
		VirtualFree( pTicket->pszRealm, 0, MEM_RELEASE );
	releasePrincipalName( &pTicket->stServiceName );
	releaseEncryptedData( &pTicket->stEncryptedPart );
	ZeroMemory( pTicket, sizeof( *pTicket ) );
}

static VOID releaseKdcReply( KDC_REP *pReply )
{
	if ( !pReply )
		return;
	if ( pReply->pszClientRealm )
		VirtualFree( pReply->pszClientRealm, 0, MEM_RELEASE );
	releasePrincipalName( &pReply->stClientName );
	releaseKerberosTicket( &pReply->stTicket );
	releaseEncryptedData( &pReply->stEncryptedPart );
	ZeroMemory( pReply, sizeof( *pReply ) );
}

static VOID releaseKdcReplyPart( ENC_KDC_REP_PART *pReplyPart )
{
	if ( !pReplyPart )
		return;
	releaseEncryptionKey( &pReplyPart->stKey );
	if ( pReplyPart->pszRealm )
		VirtualFree( pReplyPart->pszRealm, 0, MEM_RELEASE );
	releasePrincipalName( &pReplyPart->stServiceName );
	ZeroMemory( pReplyPart, sizeof( *pReplyPart ) );
}

static BOOL parseKdcReply( ASN_ELEMENT *pResponseAsn, KDC_REP *pReply )
{
	ASN_ELEMENT *pBody;
	UINT         uiFields = 0;
	LONG         lValue;
	BOOL         bFailure = TRUE;

	if ( !pResponseAsn || !pReply || pResponseAsn->iTagClass != ASN_APPLICATION ||
	     pResponseAsn->iTagValue != KERB_AS_REP || pResponseAsn->cSubElements != 1 ||
	     !asnHasTag( &pResponseAsn->pSubElements[0], ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pReply, sizeof( *pReply ) );
	pBody = &pResponseAsn->pSubElements[0];
	for ( INT iField = 0; iField < pResponseAsn->pSubElements[0].cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pBody->pSubElements[iField];

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 || pField->iTagValue < 0 ||
		     pField->iTagValue > 6 )
			goto Cleanup;
		if ( ( uiFields & ( 1U << pField->iTagValue ) ) != 0 )
			goto Cleanup;
		switch ( pField->iTagValue )
		{
		case 0:
			if ( asnGetInteger( &pField->pSubElements[0], &lValue ) || lValue != KRB_PROTOCOL_VERSION )
				goto Cleanup;
			break;
		case 1:
			if ( asnGetInteger( &pField->pSubElements[0], &lValue ) || lValue != KERB_AS_REP )
				goto Cleanup;
			break;
		case 3:
			if ( asnGetString( &pField->pSubElements[0], &pReply->pszClientRealm ) )
				goto Cleanup;
			break;
		case 4:
			if ( asnGetPrincipalName( &pField->pSubElements[0], &pReply->stClientName ) )
				goto Cleanup;
			break;
		case 5:
			if ( pField->pSubElements[0].iTagClass != ASN_APPLICATION ||
			     pField->pSubElements[0].iTagValue != KRB_TICKET_MESSAGE || pField->pSubElements[0].cSubElements != 1 ||
			     asnGetTicket( &pField->pSubElements[0].pSubElements[0], &pReply->stTicket ) )
				goto Cleanup;
			break;
		case 6:
			if ( asnGetEncryptedData( &pField->pSubElements[0], &pReply->stEncryptedPart ) )
				goto Cleanup;
			break;
		}
		uiFields |= 1U << pField->iTagValue;
	}
	if ( ( uiFields & ( ( 1U << 0 ) | ( 1U << 1 ) | ( 1U << 3 ) | ( 1U << 4 ) | ( 1U << 5 ) | ( 1U << 6 ) ) ) ==
	     ( ( 1U << 0 ) | ( 1U << 1 ) | ( 1U << 3 ) | ( 1U << 4 ) | ( 1U << 5 ) | ( 1U << 6 ) ) )
		bFailure = FALSE;

Cleanup:
	if ( bFailure )
		releaseKdcReply( pReply );
	return bFailure;
}

static BOOL buildKrbCredential( KDC_REP *pReply, ENC_KDC_REP_PART *pReplyPart, KRB_CRED *pCredential )
{
	KRB_CRED       stCredential = { 0 };
	PKRB_CRED_INFO pTicketInfo;

	if ( !pReply || !pReplyPart || !pCredential )
		return TRUE;
	stCredential.lProtocolVersion            = KRB_PROTOCOL_VERSION;
	stCredential.lMessageType                = KERB_CRED;
	stCredential.cTickets                    = 1;
	stCredential.stEncryptedPart.cTickets    = 1;
	stCredential.pTickets                    = memAlloc( sizeof( KERBEROS_TICKET ) );
	stCredential.stEncryptedPart.pTicketInfo = memAlloc( sizeof( KRB_CRED_INFO ) );
	if ( !stCredential.pTickets || !stCredential.stEncryptedPart.pTicketInfo )
		goto Failure;
	pTicketInfo                  = &stCredential.stEncryptedPart.pTicketInfo[0];
	pTicketInfo->pszClientRealm  = stringClone( pReply->pszClientRealm );
	pTicketInfo->pszServiceRealm = stringClone( pReplyPart->pszRealm );
	if ( !pTicketInfo->pszClientRealm || !pTicketInfo->pszServiceRealm )
		goto Failure;

	stCredential.pTickets[0]   = pReply->stTicket;
	pTicketInfo->stKey         = pReplyPart->stKey;
	pTicketInfo->stClientName  = pReply->stClientName;
	pTicketInfo->uiFlags       = pReplyPart->uiFlags;
	pTicketInfo->stAuthTime    = pReplyPart->stAuthTime;
	pTicketInfo->stStartTime   = pReplyPart->stStartTime;
	pTicketInfo->stEndTime     = pReplyPart->stEndTime;
	pTicketInfo->stRenewUntil  = pReplyPart->stRenewUntil;
	pTicketInfo->stServiceName = pReplyPart->stServiceName;
	ZeroMemory( &pReply->stTicket, sizeof( pReply->stTicket ) );
	ZeroMemory( &pReply->stClientName, sizeof( pReply->stClientName ) );
	ZeroMemory( &pReplyPart->stKey, sizeof( pReplyPart->stKey ) );
	ZeroMemory( &pReplyPart->stServiceName, sizeof( pReplyPart->stServiceName ) );
	*pCredential = stCredential;
	return FALSE;

Failure:
	releaseKrbCred( &stCredential );
	return TRUE;
}

BOOL encodeKrbCred( KRB_CRED *pCredential, PBYTE *ppbTicket )
{
	ASN_ELEMENT stCredentialAsn = { 0 };
	PBYTE       pbCredential    = NULL;
	INT         cbCredential    = 0;
	BOOL        bFailure        = TRUE;

	if ( !ppbTicket )
		goto Cleanup;
	*ppbTicket = NULL;
	if ( !pCredential || asnBuildKrbCredential( pCredential, &stCredentialAsn ) ||
	     asnEncode( &stCredentialAsn, &pbCredential, &cbCredential ) )
		goto Cleanup;
	*ppbTicket = ( PBYTE )base64Encode( pbCredential, ( SIZE_T )cbCredential );
	bFailure   = !*ppbTicket;

Cleanup:
	asnRelease( &stCredentialAsn );
	if ( pbCredential )
	{
		SecureZeroMemory( pbCredential, ( SIZE_T )cbCredential );
		VirtualFree( pbCredential, 0, MEM_RELEASE );
	}
	return bFailure;
}

static BOOL handleKdcRep( ASN_ELEMENT *pResponseAsn, ENCRYPTION_KEY *pReplyKey, INT iKeyUsage, UINT uiExpectedNonce,
                          KRB_CRED *pCredential )
{
	KDC_REP          stReply     = { 0 };
	ENC_KDC_REP_PART stReplyPart = { 0 };
	ASN_ELEMENT      stReplyAsn  = { 0 };
	PBYTE            pbPlaintext = NULL;
	INT              cbPlaintext = 0;
	BOOL             bSuccess    = FALSE;

	if ( !pResponseAsn || !pReplyKey || !pReplyKey->pbKey || pReplyKey->cbKey <= 0 || !pCredential ||
	     parseKdcReply( pResponseAsn, &stReply ) || stReply.stEncryptedPart.iEtype != pReplyKey->iKeyType )
		goto Cleanup;
	if ( kerberosDecrypt( stReply.stEncryptedPart.pbCipher, stReply.stEncryptedPart.cbCipher, pReplyKey, iKeyUsage,
	                      &pbPlaintext, &cbPlaintext ) ||
	     asnDecode( pbPlaintext, cbPlaintext, &stReplyAsn ) || stReplyAsn.iTagClass != ASN_APPLICATION ||
	     stReplyAsn.iTagValue != KRB_ENC_AS_REP_PART || stReplyAsn.cSubElements != 1 ||
	     asnGetEncKDCRepPart( &stReplyAsn.pSubElements[0], &stReplyPart ) )
		goto Cleanup;
	if ( stReplyPart.uiNonce != uiExpectedNonce || !stReplyPart.stKey.pbKey || stReplyPart.stKey.cbKey <= 0 ||
	     !stReplyPart.pszRealm || !stReplyPart.stServiceName.ppszNames || stReplyPart.stServiceName.cNames <= 0 )
		goto Cleanup;
	if ( buildKrbCredential( &stReply, &stReplyPart, pCredential ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	asnRelease( &stReplyAsn );
	if ( pbPlaintext )
	{
		SecureZeroMemory( pbPlaintext, ( SIZE_T )cbPlaintext );
		VirtualFree( pbPlaintext, 0, MEM_RELEASE );
	}
	releaseKdcReply( &stReply );
	releaseKdcReplyPart( &stReplyPart );
	if ( !bSuccess )
		releaseKrbCred( pCredential );
	return bSuccess;
}

static BOOL isSupportedEtype( INT iEtype )
{
	return iEtype == KRB_ETYPE_AES128_CTS_HMAC_SHA1 || iEtype == KRB_ETYPE_AES256_CTS_HMAC_SHA1 ||
	       iEtype == KRB_ETYPE_RC4_HMAC;
}

BOOL parseEtype( PCSTR pszValue, PINT piEtype )
{
	if ( !pszValue || !piEtype )
		return FALSE;
	*piEtype = 0;
	if ( _stricmp( pszValue, RN_DEFAULT_ETYPE ) == 0 )
		*piEtype = KRB_ETYPE_AES256_CTS_HMAC_SHA1;
	else if ( _stricmp( pszValue, "AES128" ) == 0 )
		*piEtype = KRB_ETYPE_AES128_CTS_HMAC_SHA1;
	else if ( _stricmp( pszValue, "RC4" ) == 0 )
		*piEtype = KRB_ETYPE_RC4_HMAC;
	else
		return FALSE;
	return TRUE;
}

static VOID releaseAsRequest( AS_REQ *pRequest )
{
	if ( !pRequest )
		return;
	if ( pRequest->pPaData )
	{
		for ( INT iPaData = 0; iPaData < pRequest->cPaData; iPaData++ )
		{
			PPA_DATA pPaData = &pRequest->pPaData[iPaData];

			if ( pPaData->pvValue )
			{
				if ( pPaData->uiType == PADATA_ENC_TIMESTAMP )
					releaseEncryptedData( pPaData->pvValue );
				VirtualFree( pPaData->pvValue, 0, MEM_RELEASE );
			}
		}
		VirtualFree( pRequest->pPaData, 0, MEM_RELEASE );
	}
	if ( pRequest->stRequestBody.pszRealm )
		VirtualFree( pRequest->stRequestBody.pszRealm, 0, MEM_RELEASE );
	releasePrincipalName( &pRequest->stRequestBody.stClientName );
	releasePrincipalName( &pRequest->stRequestBody.stServiceName );
	ZeroMemory( pRequest, sizeof( *pRequest ) );
}

static BOOL buildAsRequest( PCSTR pszUser, PCSTR pszDomain, ENCRYPTION_KEY *pPasswordKey, INT iRequestedEtype,
                            BOOL bEnterprise, BOOL bWithPreauth, PCSTR pszServiceClass, PCSTR pszServiceInstance,
                            AS_REQ *pRequest )
{
	PKERB_PA_PAC_REQUEST pPacRequest;
	INT                   iPacIndex;

	if ( !pszUser || !pszDomain || !pszServiceClass || !pszServiceInstance || !pRequest ||
	     !isSupportedEtype( iRequestedEtype ) || ( bWithPreauth && !pPasswordKey ) )
		return TRUE;
	ZeroMemory( pRequest, sizeof( *pRequest ) );
	pRequest->lProtocolVersion                      = KRB_PROTOCOL_VERSION;
	pRequest->lMessageType                          = KERB_AS_REQ;
	pRequest->cPaData                               = bWithPreauth ? 2 : 1;
	pRequest->stRequestBody.stClientName.lNameType  = bEnterprise ? PRINCIPAL_NT_ENTERPRISE : PRINCIPAL_NT_PRINCIPAL;
	pRequest->stRequestBody.stClientName.cNames     = 1;
	pRequest->stRequestBody.stServiceName.lNameType = PRINCIPAL_NT_SRV_INST;
	pRequest->stRequestBody.stServiceName.cNames    = 2;
	pRequest->stRequestBody.uiOptions               = KRB_KDC_OPTION_FORWARDABLE | KRB_KDC_OPTION_RENEWABLE |
	                                                  KRB_KDC_OPTION_RENEWABLE_OK;
	pRequest->stRequestBody.uiLifetime              = KRB_DEFAULT_TICKET_LIFETIME;
	pRequest->stRequestBody.iEtype                  = iRequestedEtype;

	if ( !SystemFunction036( &pRequest->stRequestBody.uiNonce, sizeof( pRequest->stRequestBody.uiNonce ) ) )
		goto Failure;
	pRequest->stRequestBody.uiNonce &= ( UINT )INT_MAX;
	pRequest->stRequestBody.pszRealm = stringClone( pszDomain );
	if ( !pRequest->stRequestBody.pszRealm )
		goto Failure;

	pRequest->pPaData = memAlloc( sizeof( PA_DATA ) * ( SIZE_T )pRequest->cPaData );
	pRequest->stRequestBody.stClientName.ppszNames = memAlloc( sizeof( PCHAR ) );
	pRequest->stRequestBody.stServiceName.ppszNames =
		memAlloc( sizeof( PCHAR ) * ( SIZE_T )pRequest->stRequestBody.stServiceName.cNames );
	if ( !pRequest->pPaData || !pRequest->stRequestBody.stClientName.ppszNames ||
	     !pRequest->stRequestBody.stServiceName.ppszNames )
		goto Failure;

	pRequest->stRequestBody.stClientName.ppszNames[0]  = stringClone( pszUser );
	pRequest->stRequestBody.stServiceName.ppszNames[0] = stringClone( pszServiceClass );
	pRequest->stRequestBody.stServiceName.ppszNames[1] = stringClone( pszServiceInstance );
	if ( !pRequest->stRequestBody.stClientName.ppszNames[0] || !pRequest->stRequestBody.stServiceName.ppszNames[0] ||
	     !pRequest->stRequestBody.stServiceName.ppszNames[1] )
		goto Failure;
	if ( bWithPreauth && asnCreateEncryptedTimestampPaData( pPasswordKey, &pRequest->pPaData[0] ) )
		goto Failure;
	iPacIndex                            = bWithPreauth ? 1 : 0;
	pPacRequest                          = memAlloc( sizeof( *pPacRequest ) );
	if ( !pPacRequest )
		goto Failure;
	pPacRequest->bIncludePac             = TRUE;
	pRequest->pPaData[iPacIndex].uiType  = PADATA_PA_PAC_REQUEST;
	pRequest->pPaData[iPacIndex].pvValue = pPacRequest;
	return FALSE;

Failure:
	releaseAsRequest( pRequest );
	return TRUE;
}

static BOOL getKdcErrorCodeStrict( ASN_ELEMENT *pResponseAsn, PUINT puiError )
{
	ASN_ELEMENT *pBody;
	LONG         lError;
	BOOL         bFound = FALSE;

	if ( !pResponseAsn || !puiError || pResponseAsn->iTagClass != ASN_APPLICATION ||
	     pResponseAsn->iTagValue != KERB_ERROR || pResponseAsn->cSubElements != 1 )
		return TRUE;
	*puiError = 0;
	pBody     = &pResponseAsn->pSubElements[0];
	if ( !asnHasTag( pBody, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;

	for ( INT iField = 0; iField < pBody->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pBody->pSubElements[iField];

		if ( pField->iTagClass == ASN_CONTEXT && pField->iTagValue == 6 )
		{
			if ( bFound || pField->cSubElements != 1 || asnGetInteger( &pField->pSubElements[0], &lError ) ||
			     lError < 0 )
				return TRUE;
			*puiError = ( UINT )lError;
			bFound    = TRUE;
		}
	}
	return !bFound;
}

static BOOL parseEtypeInfo2Value( PBYTE pbValue, INT cbValue, INT iEtype, PCHAR pszSalt, SIZE_T cchSalt,
                                  PULONG pulIterations )
{
	ASN_ELEMENT stInfoAsn    = { 0 };
	PCHAR       pszEntrySalt = NULL;
	PBYTE       pbParams     = NULL;
	INT         cbParams     = 0;
	BOOL        bFailure     = TRUE;

	if ( !pbValue || cbValue <= 0 || cbValue > KRB_MAX_ETYPE_INFO2_SIZE || !pszSalt || cchSalt == 0 || !pulIterations ||
	     asnDecode( pbValue, cbValue, &stInfoAsn ) || !asnHasTag( &stInfoAsn, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		goto Cleanup;

	for ( INT iEntry = 0; iEntry < stInfoAsn.cSubElements; iEntry++ )
	{
		ASN_ELEMENT *pEntry        = &stInfoAsn.pSubElements[iEntry];
		ASN_ELEMENT *pSaltNode     = NULL;
		ASN_ELEMENT *pParamsNode   = NULL;
		LONG         lEntryEtype   = -1;
		SIZE_T       cchEntrySalt  = 0;
		ULONG        ulIterations  = KRB_DEFAULT_S2K_ITERATIONS;
		UINT         uiEntryFields = 0;

		if ( !asnHasTag( pEntry, ASN_UNIVERSAL, ASN_SEQUENCE ) )
			goto Cleanup;
		for ( INT iField = 0; iField < pEntry->cSubElements; iField++ )
		{
			ASN_ELEMENT *pField = &pEntry->pSubElements[iField];

			if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 || pField->iTagValue < 0 ||
			     pField->iTagValue > 2 || ( uiEntryFields & ( 1U << pField->iTagValue ) ) != 0 )
				goto Cleanup;
			uiEntryFields |= 1U << pField->iTagValue;
			if ( pField->iTagValue == 0 )
			{
				if ( asnGetInteger( &pField->pSubElements[0], &lEntryEtype ) )
					goto Cleanup;
			}
			else if ( pField->iTagValue == 1 )
			{
				pSaltNode = pField;
			}
			else if ( pField->iTagValue == 2 )
			{
				pParamsNode = pField;
			}
		}
		if ( ( uiEntryFields & 1U ) == 0 )
			goto Cleanup;
		if ( lEntryEtype != iEtype )
			continue;
		if ( pSaltNode )
		{
			if ( !asnHasTag( &pSaltNode->pSubElements[0], ASN_UNIVERSAL, ASN_GENERAL_STRING ) )
				goto Cleanup;
			if ( pSaltNode->pSubElements[0].cbValue <= 0 || pSaltNode->pSubElements[0].cbValue > KRB_MAX_SALT_SIZE ||
			     asnGetString( &pSaltNode->pSubElements[0], &pszEntrySalt ) )
				goto Cleanup;
			cchEntrySalt = strlen( pszEntrySalt );
			if ( cchEntrySalt == 0 || cchEntrySalt >= cchSalt )
				goto Cleanup;
		}
		else if ( !pszSalt[0] )
		{
			goto Cleanup;
		}

		if ( pParamsNode )
		{
			if ( !asnHasTag( &pParamsNode->pSubElements[0], ASN_UNIVERSAL, ASN_OCTET_STRING ) ||
			     asnGetOctetString( &pParamsNode->pSubElements[0], &pbParams, &cbParams ) || cbParams != 4 )
				goto Cleanup;
			ulIterations = ( ( ULONG )pbParams[0] << 24 ) | ( ( ULONG )pbParams[1] << 16 ) |
			               ( ( ULONG )pbParams[2] << 8 ) | ( ULONG )pbParams[3];
			if ( ulIterations == 0 || ulIterations > KRB_MAX_S2K_ITERATIONS )
				goto Cleanup;
		}

		if ( pszEntrySalt && !stringCopy( pszSalt, cchSalt, pszEntrySalt ) )
			goto Cleanup;
		*pulIterations = ulIterations;
		bFailure       = FALSE;
		goto Cleanup;
	}

Cleanup:
	asnRelease( &stInfoAsn );
	if ( pszEntrySalt )
	{
		SecureZeroMemory( pszEntrySalt, strlen( pszEntrySalt ) );
		VirtualFree( pszEntrySalt, 0, MEM_RELEASE );
	}
	if ( pbParams )
	{
		SecureZeroMemory( pbParams, ( SIZE_T )cbParams );
		VirtualFree( pbParams, 0, MEM_RELEASE );
	}
	return bFailure;
}

static BOOL parsePreauthParameters( ASN_ELEMENT *pResponseAsn, INT iEtype, PCHAR pszSalt, SIZE_T cchSalt,
                                    PULONG pulIterations )
{
	ASN_ELEMENT *pBody;
	ASN_ELEMENT  stMethodAsn = { 0 };
	PBYTE        pbMethod    = NULL;
	PBYTE        pbInfo      = NULL;
	INT          cbMethod    = 0;
	INT          cbInfo      = 0;
	UINT         uiError     = 0;
	BOOL         bFailure    = TRUE;

	if ( getKdcErrorCodeStrict( pResponseAsn, &uiError ) || uiError != KRB_ERR_PREAUTH_REQUIRED ||
	     pResponseAsn->cSubElements != 1 )
		goto Cleanup;
	pBody = &pResponseAsn->pSubElements[0];

	for ( INT iField = 0; iField < pBody->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pBody->pSubElements[iField];

		if ( pField->iTagClass == ASN_CONTEXT && pField->iTagValue == 12 && pField->cSubElements == 1 &&
		     asnHasTag( &pField->pSubElements[0], ASN_UNIVERSAL, ASN_OCTET_STRING ) &&
		     !asnGetOctetString( &pField->pSubElements[0], &pbMethod, &cbMethod ) )
			break;
	}
	if ( !pbMethod || cbMethod <= 0 || cbMethod > KRB_MAX_ETYPE_INFO2_SIZE ||
	     asnDecode( pbMethod, cbMethod, &stMethodAsn ) || !asnHasTag( &stMethodAsn, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		goto Cleanup;

	for ( INT iPa = 0; iPa < stMethodAsn.cSubElements; iPa++ )
	{
		ASN_ELEMENT *pPa        = &stMethodAsn.pSubElements[iPa];
		ASN_ELEMENT *pValue     = NULL;
		LONG         lPaType    = -1;
		UINT         uiPaFields = 0;

		if ( !asnHasTag( pPa, ASN_UNIVERSAL, ASN_SEQUENCE ) )
			goto Cleanup;
		for ( INT iField = 0; iField < pPa->cSubElements; iField++ )
		{
			ASN_ELEMENT *pField = &pPa->pSubElements[iField];

			if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 || pField->iTagValue < 1 ||
			     pField->iTagValue > 2 || ( uiPaFields & ( 1U << pField->iTagValue ) ) != 0 )
				goto Cleanup;
			uiPaFields |= 1U << pField->iTagValue;
			if ( pField->iTagValue == 1 )
			{
				if ( asnGetInteger( &pField->pSubElements[0], &lPaType ) )
					goto Cleanup;
			}
			else if ( pField->iTagValue == 2 )
			{
				pValue = pField;
			}
		}
		if ( ( uiPaFields & ( ( 1U << 1 ) | ( 1U << 2 ) ) ) != ( ( 1U << 1 ) | ( 1U << 2 ) ) )
			goto Cleanup;
		if ( lPaType != PADATA_ETYPE_INFO2 || !asnHasTag( &pValue->pSubElements[0], ASN_UNIVERSAL, ASN_OCTET_STRING ) )
			continue;
		if ( asnGetOctetString( &pValue->pSubElements[0], &pbInfo, &cbInfo ) )
			goto Cleanup;
		bFailure = parseEtypeInfo2Value( pbInfo, cbInfo, iEtype, pszSalt, cchSalt, pulIterations );
		goto Cleanup;
	}

Cleanup:
	asnRelease( &stMethodAsn );
	if ( pbMethod )
		VirtualFree( pbMethod, 0, MEM_RELEASE );
	if ( pbInfo )
		VirtualFree( pbInfo, 0, MEM_RELEASE );
	return bFailure;
}

static BOOL discoverPreauthParameters( PCSTR pszPrincipal, PCSTR pszDomain, PCSTR pszDc, INT iEtype, PCHAR pszSalt,
                                       SIZE_T cchSalt, PULONG pulIterations )
{
	AS_REQ      stRequest     = { 0 };
	ASN_ELEMENT stRequestAsn  = { 0 };
	ASN_ELEMENT stResponseAsn = { 0 };
	PBYTE       pbRequest     = NULL;
	PBYTE       pbResponse    = NULL;
	INT         cbRequest     = 0;
	INT         cbResponse    = 0;
	INT         cchSaltResult;
	BOOL        bSuccess = FALSE;

	if ( !pszPrincipal || !pszDomain || !pszDc || !pszSalt || !pulIterations )
		goto Cleanup;
	cchSaltResult = snprintf( pszSalt, cchSalt, "%s%s", pszDomain, pszPrincipal );
	if ( cchSaltResult < 0 || ( SIZE_T )cchSaltResult >= cchSalt )
		goto Cleanup;
	CharUpperBuffA( pszSalt, ( DWORD )strlen( pszDomain ) );
	*pulIterations = KRB_DEFAULT_S2K_ITERATIONS;

	if ( buildAsRequest( pszPrincipal, pszDomain, NULL, iEtype, FALSE, FALSE, RN_TICKET_GRANTING_SERVICE, pszDomain,
	                     &stRequest ) )
	{
		printf( "[-] No se pudo construir AS-REQ de descubrimiento.\n" );
		goto Cleanup;
	}
	if ( asnBuildAsRequest( &stRequest, &stRequestAsn ) || asnEncode( &stRequestAsn, &pbRequest, &cbRequest ) )
	{
		printf( "[-] No se pudo codificar AS-REQ de descubrimiento.\n" );
		goto Cleanup;
	}
	if ( !sendKerberosRequest( pszDc, KRB_KDC_PORT, pbRequest, cbRequest, &pbResponse, &cbResponse ) )
	{
		printf( "[-] Fallo el transporte TCP con el KDC durante el descubrimiento.\n" );
		goto Cleanup;
	}
	if ( asnDecode( pbResponse, cbResponse, &stResponseAsn ) )
	{
		printf( "[-] Respuesta KDC no valida durante el descubrimiento: %d bytes.\n", cbResponse );
		goto Cleanup;
	}
	if ( parsePreauthParameters( &stResponseAsn, iEtype, pszSalt, cchSalt, pulIterations ) )
	{
		UINT uiKdcError;

		if ( !getKdcErrorCodeStrict( &stResponseAsn, &uiKdcError ) && uiKdcError != KRB_ERR_PREAUTH_REQUIRED )
			printf( "[-] KDC error durante preautenticacion: %u.\n", uiKdcError );
		else
			printf( "[-] KDC sin ETYPE-INFO2 utilizable para etype %d.\n", iEtype );
		goto Cleanup;
	}

	bSuccess = TRUE;

Cleanup:
	asnRelease( &stRequestAsn );
	asnRelease( &stResponseAsn );
	releaseAsRequest( &stRequest );
	if ( pbRequest )
		VirtualFree( pbRequest, 0, MEM_RELEASE );
	if ( pbResponse )
		VirtualFree( pbResponse, 0, MEM_RELEASE );
	return bSuccess;
}

BOOL askAsTicketWithPasswordForPrincipal( PCSTR pszRequestPrincipal, PCSTR pszSaltPrincipal, PCSTR pszDomain,
                                          PCSTR pszPassword, PCSTR pszDc, INT iCredentialEtype, INT iRequestedEtype,
                                          BOOL bEnterprise, PCSTR pszServiceClass, PCSTR pszServiceInstance,
                                          KRB_CRED *pCredential )
{
	ENCRYPTION_KEY stPasswordKey = { 0 };
	AS_REQ         stRequest     = { 0 };
	ASN_ELEMENT    stRequestAsn  = { 0 };
	ASN_ELEMENT    stResponseAsn = { 0 };
	PBYTE          pbRequest     = NULL;
	PBYTE          pbResponse    = NULL;
	INT            cbRequest     = 0;
	INT            cbResponse    = 0;
	INT            iReplyUsage;
	ULONG          ulIterations                  = KRB_DEFAULT_S2K_ITERATIONS;
	CHAR           szSalt[KRB_MAX_SALT_SIZE + 1] = { 0 };
	BOOL           bSuccess                      = FALSE;

	if ( !pszRequestPrincipal || !pszSaltPrincipal || !pszDomain || !pszPassword || !pszDc || !pCredential ||
	     !isSupportedEtype( iCredentialEtype ) || !isSupportedEtype( iRequestedEtype ) )
		return FALSE;

	ZeroMemory( pCredential, sizeof( *pCredential ) );
	iReplyUsage =
		( iCredentialEtype == KRB_ETYPE_AES128_CTS_HMAC_SHA1 || iCredentialEtype == KRB_ETYPE_AES256_CTS_HMAC_SHA1 )
			? KRB_KEY_USAGE_AS_REP_AES
			: KRB_KEY_USAGE_AS_REP_RC4;

	if ( iCredentialEtype != KRB_ETYPE_RC4_HMAC &&
	     !discoverPreauthParameters( pszSaltPrincipal, pszDomain, pszDc, iCredentialEtype, szSalt, ARRAYSIZE( szSalt ),
	                                 &ulIterations ) )
		goto Cleanup;
	if ( getPasswordKey( pszPassword, szSalt, ulIterations, iCredentialEtype, &stPasswordKey ) )
	{
		printf( "[-] No se pudo derivar la clave Kerberos para etype %d.\n", iCredentialEtype );
		goto Cleanup;
	}
	if ( buildAsRequest( pszRequestPrincipal, pszDomain, &stPasswordKey, iRequestedEtype, bEnterprise, TRUE,
	                     pszServiceClass, pszServiceInstance, &stRequest ) )
	{
		printf( "[-] No se pudo construir AS-REQ autenticado.\n" );
		goto Cleanup;
	}
	if ( asnBuildAsRequest( &stRequest, &stRequestAsn ) || asnEncode( &stRequestAsn, &pbRequest, &cbRequest ) )
	{
		printf( "[-] No se pudo codificar AS-REQ autenticado.\n" );
		goto Cleanup;
	}
	if ( !sendKerberosRequest( pszDc, KRB_KDC_PORT, pbRequest, cbRequest, &pbResponse, &cbResponse ) )
	{
		printf( "[-] Fallo el transporte TCP con el KDC durante AS-REQ autenticado.\n" );
		goto Cleanup;
	}
	if ( asnDecode( pbResponse, cbResponse, &stResponseAsn ) )
	{
		printf( "[-] Respuesta KDC no valida durante AS-REQ autenticado: %d bytes.\n", cbResponse );
		goto Cleanup;
	}

	if ( stResponseAsn.iTagClass == ASN_APPLICATION && stResponseAsn.iTagValue == KERB_AS_REP )
	{
		bSuccess =
			handleKdcRep( &stResponseAsn, &stPasswordKey, iReplyUsage, stRequest.stRequestBody.uiNonce, pCredential );
		if ( !bSuccess )
			printf( "[-] AS-REP no se pudo validar o descifrar.\n" );
	}
	else
	{
		UINT uiKdcError;

		if ( !getKdcErrorCodeStrict( &stResponseAsn, &uiKdcError ) )
			printf( "[-] KDC rechazo AS-REQ: %u.\n", uiKdcError );
		else
			printf( "[-] Respuesta KDC inesperada: clase %d, etiqueta %d.\n", stResponseAsn.iTagClass,
			        stResponseAsn.iTagValue );
	}

Cleanup:
	SecureZeroMemory( szSalt, sizeof( szSalt ) );
	asnRelease( &stRequestAsn );
	asnRelease( &stResponseAsn );
	releaseAsRequest( &stRequest );
	releaseEncryptionKey( &stPasswordKey );
	if ( pbRequest )
		VirtualFree( pbRequest, 0, MEM_RELEASE );
	if ( pbResponse )
		VirtualFree( pbResponse, 0, MEM_RELEASE );
	return bSuccess;
}

BOOL askTgtWithPasswordForPrincipal( PCSTR pszRequestPrincipal, PCSTR pszSaltPrincipal, PCSTR pszDomain,
                                     PCSTR pszPassword, PCSTR pszDc, INT iEtype, BOOL bEnterprise,
                                     KRB_CRED *pCredential )
{
	return askAsTicketWithPasswordForPrincipal( pszRequestPrincipal, pszSaltPrincipal, pszDomain, pszPassword, pszDc,
	                                            iEtype, iEtype, bEnterprise, RN_TICKET_GRANTING_SERVICE, pszDomain,
	                                            pCredential );
}

BOOL getKrbCredIdentity( KRB_CRED *pCredential, PCHAR pszPrincipal, SIZE_T cchPrincipal, PCHAR pszRealm,
                         SIZE_T cchRealm )
{
	KRB_CRED_INFO *pInfo;
	SIZE_T         iOutput = 0;

	if ( !pCredential || !pszPrincipal || !cchPrincipal || !pszRealm || !cchRealm ||
	     pCredential->stEncryptedPart.cTickets < 1 || !pCredential->stEncryptedPart.pTicketInfo )
		return FALSE;

	pInfo = &pCredential->stEncryptedPart.pTicketInfo[0];
	if ( !pInfo->pszClientRealm || pInfo->stClientName.cNames < 1 || !pInfo->stClientName.ppszNames )
		return FALSE;
	for ( INT iName = 0; iName < pInfo->stClientName.cNames; iName++ )
	{
		if ( !pInfo->stClientName.ppszNames[iName] )
			return FALSE;
		SIZE_T cchName = strlen( pInfo->stClientName.ppszNames[iName] );
		if ( iOutput + cchName + ( iName ? 1 : 0 ) >= cchPrincipal )
			return FALSE;
		if ( iName )
			pszPrincipal[iOutput++] = '/';
		memcpy( pszPrincipal + iOutput, pInfo->stClientName.ppszNames[iName], cchName );
		iOutput += cchName;
	}
	pszPrincipal[iOutput] = 0;
	if ( !stringCopy( pszRealm, cchRealm, pInfo->pszClientRealm ) )
		return FALSE;
	return TRUE;
}

BOOL krbCredHasService( KRB_CRED *pCredential, PCSTR pszRealm, PCSTR pszServiceClass, PCSTR pszServiceInstance )
{
	KERBEROS_TICKET *pTicket;
	KRB_CRED_INFO   *pInfo;

	if ( !pCredential || !pszRealm || !pszServiceClass || !pszServiceInstance || pCredential->cTickets < 1 ||
	     !pCredential->pTickets || pCredential->stEncryptedPart.cTickets < 1 ||
	     !pCredential->stEncryptedPart.pTicketInfo )
		return FALSE;
	pTicket = &pCredential->pTickets[0];
	pInfo   = &pCredential->stEncryptedPart.pTicketInfo[0];
	if ( !pTicket->pszRealm || pTicket->stServiceName.cNames != 2 || !pTicket->stServiceName.ppszNames ||
	     !pTicket->stServiceName.ppszNames[0] || !pTicket->stServiceName.ppszNames[1] || !pInfo->pszServiceRealm ||
	     pInfo->stServiceName.cNames != 2 || !pInfo->stServiceName.ppszNames || !pInfo->stServiceName.ppszNames[0] ||
	     !pInfo->stServiceName.ppszNames[1] )
		return FALSE;
	return _stricmp( pTicket->pszRealm, pszRealm ) == 0 &&
	       _stricmp( pTicket->stServiceName.ppszNames[0], pszServiceClass ) == 0 &&
	       _stricmp( pTicket->stServiceName.ppszNames[1], pszServiceInstance ) == 0 &&
	       _stricmp( pInfo->pszServiceRealm, pszRealm ) == 0 &&
	       _stricmp( pInfo->stServiceName.ppszNames[0], pszServiceClass ) == 0 &&
	       _stricmp( pInfo->stServiceName.ppszNames[1], pszServiceInstance ) == 0;
}

VOID releaseKrbCred( KRB_CRED *pCredential )
{
	if ( !pCredential )
		return;
	if ( pCredential->pTickets )
	{
		for ( INT iTicket = 0; iTicket < pCredential->cTickets; iTicket++ )
			releaseKerberosTicket( &pCredential->pTickets[iTicket] );
		VirtualFree( pCredential->pTickets, 0, MEM_RELEASE );
	}
	if ( pCredential->stEncryptedPart.pTicketInfo )
	{
		for ( INT iInfo = 0; iInfo < pCredential->stEncryptedPart.cTickets; iInfo++ )
		{
			KRB_CRED_INFO *pInfo = &pCredential->stEncryptedPart.pTicketInfo[iInfo];

			releaseEncryptionKey( &pInfo->stKey );
			if ( pInfo->pszClientRealm )
				VirtualFree( pInfo->pszClientRealm, 0, MEM_RELEASE );
			releasePrincipalName( &pInfo->stClientName );
			if ( pInfo->pszServiceRealm )
				VirtualFree( pInfo->pszServiceRealm, 0, MEM_RELEASE );
			releasePrincipalName( &pInfo->stServiceName );
		}
		VirtualFree( pCredential->stEncryptedPart.pTicketInfo, 0, MEM_RELEASE );
	}
	ZeroMemory( pCredential, sizeof( *pCredential ) );
}

VOID releaseBase64Ticket( PBYTE *ppbTicket )
{
	if ( ppbTicket && *ppbTicket )
	{
		SecureZeroMemory( *ppbTicket, strlen( ( PCSTR )*ppbTicket ) );
		VirtualFree( *ppbTicket, 0, MEM_RELEASE );
		*ppbTicket = NULL;
	}
}
