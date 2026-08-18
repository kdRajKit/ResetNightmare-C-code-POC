/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        kpasswd.c                                                                                            *
*   DESCRIPCION:   Construccion y validacion del intercambio RFC 3244 sobre TCP/464.                                   *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                              IMPLEMENTACION KPASSWD                                                  *
***********************************************************************************************************************/

static VOID writeNetworkUshort( PBYTE pbValue, USHORT usValue )
{
	pbValue[0] = ( BYTE )( usValue >> 8 );
	pbValue[1] = ( BYTE )usValue;
}

static USHORT readNetworkUshort( const BYTE *pbValue )
{
	return ( USHORT )( ( ( USHORT )pbValue[0] << 8 ) | pbValue[1] );
}

static BOOL generateRandomKey( INT iEtype, ENCRYPTION_KEY *pKey )
{
	PKERB_ECRYPT pCrypto = NULL;

	if ( !pKey || iEtype < 0 )
		return FALSE;
	ZeroMemory( pKey, sizeof( *pKey ) );
	if ( !NT_SUCCESS( CDLocateCSystem( ( ULONG )iEtype, &pCrypto ) ) || !pCrypto || pCrypto->cbKey == 0 ||
		 pCrypto->cbKey > INT_MAX )
		return FALSE;
	pKey->iKeyType = iEtype;
	pKey->cbKey	   = ( INT )pCrypto->cbKey;
	pKey->pbKey	   = memAlloc( pCrypto->cbKey );
	if ( pKey->pbKey && SystemFunction036( pKey->pbKey, ( ULONG )pKey->cbKey ) )
		return TRUE;
	releaseEncryptionKey( pKey );
	return FALSE;
}

static BOOL generateSequenceNumber( PUINT puiSequence )
{
	if ( !puiSequence )
		return FALSE;
	do
	{
		if ( !SystemFunction036( puiSequence, sizeof( *puiSequence ) ) )
			return FALSE;
	} while ( *puiSequence == 0 );
	return TRUE;
}

static BOOL encodeChangePasswdData( PCSTR pszPassword, PBYTE *ppbData, PINT pcbData )
{
	ASN_ELEMENT stPassword = { 0 };
	ASN_ELEMENT stBody	   = { 0 };
	SIZE_T		cchPassword;
	BOOL		bSuccess = FALSE;

	if ( !ppbData || !pcbData )
		goto Cleanup;
	*ppbData = NULL;
	*pcbData = 0;
	if ( !pszPassword )
		goto Cleanup;
	cchPassword = strlen( pszPassword );
	if ( cchPassword == 0 || cchPassword > INT_MAX ||
		 asnPackOctetString( 0, ( PBYTE )pszPassword, ( INT )cchPassword, &stPassword ) ||
		 asnMakeSequence( &stPassword, 1, &stBody ) || asnEncode( &stBody, ppbData, pcbData ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	asnRelease( &stPassword );
	asnRelease( &stBody );
	return bSuccess;
}

static BOOL encodeSenderAddress( ASN_ELEMENT *pContext )
{
	BYTE		abyAddress[sizeof( ULONG )] = { 0 };
	ASN_ELEMENT astFields[2]				= { 0 };
	ASN_ELEMENT stBody						= { 0 };
	BOOL		bSuccess					= FALSE;

	if ( !pContext )
		goto Cleanup;
	if ( asnPackInteger( 0, KRB_ADDRESS_DIRECTIONAL, &astFields[0] ) ||
		 asnPackOctetString( 1, abyAddress, sizeof( abyAddress ), &astFields[1] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_CONTEXT, 4, &stBody, pContext ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stBody );
	return bSuccess;
}

static BOOL encodeEncKrbPrivPart( PBYTE pbUserData, INT cbUserData, LONG lMicroseconds, UINT uiSequence,
								  PBYTE *ppbData, PINT pcbData )
{
	ASN_ELEMENT astFields[4]  = { 0 };
	ASN_ELEMENT stBody		  = { 0 };
	ASN_ELEMENT stApplication = { 0 };
	BOOL		bSuccess	  = FALSE;

	if ( !ppbData || !pcbData )
		goto Cleanup;
	*ppbData = NULL;
	*pcbData = 0;
	if ( !pbUserData || cbUserData <= 0 || lMicroseconds < 0 || lMicroseconds > 999999 )
		goto Cleanup;
	if ( asnPackOctetString( 0, pbUserData, cbUserData, &astFields[0] ) ||
		 asnPackInteger( 2, lMicroseconds, &astFields[1] ) || asnPackUnsignedInteger( 3, uiSequence, &astFields[2] ) ||
		 !encodeSenderAddress( &astFields[3] ) || asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KRB_ENC_PRIV_PART_MESSAGE, &stBody, &stApplication ) ||
		 asnEncode( &stApplication, ppbData, pcbData ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stBody );
	asnRelease( &stApplication );
	return bSuccess;
}

static BOOL encodeKrbPriv( PBYTE pbPlaintext, INT cbPlaintext, ENCRYPTION_KEY *pSubkey, PBYTE *ppbData, PINT pcbData )
{
	ENCRYPTED_DATA stCipher		 = { 0 };
	ASN_ELEMENT	   astFields[3]	 = { 0 };
	ASN_ELEMENT	   stValue		 = { 0 };
	ASN_ELEMENT	   stBody		 = { 0 };
	ASN_ELEMENT	   stApplication = { 0 };
	BOOL		   bSuccess		 = FALSE;

	if ( !ppbData || !pcbData )
		goto Cleanup;
	*ppbData = NULL;
	*pcbData = 0;
	if ( !pbPlaintext || cbPlaintext <= 0 || !pSubkey || !pSubkey->pbKey || pSubkey->cbKey <= 0 )
		goto Cleanup;
	stCipher.iEtype = pSubkey->iKeyType;
	if ( kerberosEncrypt( pbPlaintext, cbPlaintext, pSubkey, KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, &stCipher.pbCipher,
						  &stCipher.cbCipher ) ||
		 asnPackInteger( 0, KRB_PROTOCOL_VERSION, &astFields[0] ) ||
		 asnPackInteger( 1, KRB_PRIV_MESSAGE, &astFields[1] ) || asnBuildEncryptedData( &stCipher, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 3, &stValue, &astFields[2] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KRB_PRIV_MESSAGE, &stBody, &stApplication ) ||
		 asnEncode( &stApplication, ppbData, pcbData ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	asnRelease( &stBody );
	asnRelease( &stApplication );
	releaseEncryptedData( &stCipher );
	return bSuccess;
}

static BOOL findContextNode( ASN_ELEMENT *pApplication, INT iTag, ASN_ELEMENT **ppNode )
{
	ASN_ELEMENT *pBody;

	if ( !ppNode )
		return FALSE;
	*ppNode = NULL;
	if ( !pApplication || pApplication->cSubElements != 1 ||
		 pApplication->pSubElements[0].iTagClass != ASN_UNIVERSAL ||
		 pApplication->pSubElements[0].iTagValue != ASN_SEQUENCE )
		return FALSE;
	pBody = &pApplication->pSubElements[0];
	for ( INT iNode = 0; iNode < pBody->cSubElements; iNode++ )
	{
		if ( pBody->pSubElements[iNode].iTagClass == ASN_CONTEXT && pBody->pSubElements[iNode].iTagValue == iTag )
		{
			if ( *ppNode || pBody->pSubElements[iNode].cSubElements != 1 )
			{
				*ppNode = NULL;
				return FALSE;
			}
			*ppNode = &pBody->pSubElements[iNode];
		}
	}
	return *ppNode != NULL;
}

static BOOL parseKpasswdResponse( PBYTE pbResponse, INT cbResponse, ENCRYPTION_KEY *pSubkey, PUSHORT pusResult )
{
	USHORT		   cbMessage;
	USHORT		   usVersion;
	USHORT		   cbApReply;
	PBYTE		   pbPrivate;
	INT			   cbPrivate;
	ASN_ELEMENT	   stPrivateAsn = { 0 };
	ASN_ELEMENT	   stPlainAsn	= { 0 };
	ASN_ELEMENT	   stErrorAsn	= { 0 };
	ASN_ELEMENT	  *pCipherNode;
	ASN_ELEMENT	  *pDataNode;
	ASN_ELEMENT	  *pErrorDataNode;
	ENCRYPTED_DATA stCipher	   = { 0 };
	PBYTE		   pbPlaintext = NULL;
	INT			   cbPlaintext = 0;
	PBYTE		   pbResult	   = NULL;
	INT			   cbResult	   = 0;
	BOOL		   bSuccess	   = FALSE;

	if ( !pbResponse || cbResponse <= 0 || !pSubkey || !pSubkey->pbKey || pSubkey->cbKey <= 0 || !pusResult )
		goto Cleanup;
	*pusResult = USHRT_MAX;
	if ( !asnDecode( pbResponse, cbResponse, &stErrorAsn ) && stErrorAsn.iTagClass == ASN_APPLICATION &&
		 stErrorAsn.iTagValue == KERB_ERROR )
	{
		if ( findContextNode( &stErrorAsn, 12, &pErrorDataNode ) &&
			 !asnGetOctetString( &pErrorDataNode->pSubElements[0], &pbResult, &cbResult ) && cbResult >= 2 )
		{
			*pusResult = readNetworkUshort( pbResult );
			bSuccess   = TRUE;
		}
		goto Cleanup;
	}
	if ( cbResponse < KRB_KPASSWD_HEADER_SIZE )
		goto Cleanup;
	cbMessage = readNetworkUshort( pbResponse );
	usVersion = readNetworkUshort( pbResponse + 2 );
	cbApReply = readNetworkUshort( pbResponse + 4 );
	if ( cbMessage != cbResponse || usVersion != KRB_KPASSWD_RESPONSE_VERSION || cbApReply == 0 ||
		 KRB_KPASSWD_HEADER_SIZE + ( INT )cbApReply >= cbResponse )
		goto Cleanup;

	pbPrivate = pbResponse + KRB_KPASSWD_HEADER_SIZE + cbApReply;
	cbPrivate = cbResponse - KRB_KPASSWD_HEADER_SIZE - cbApReply;
	if ( asnDecode( pbPrivate, cbPrivate, &stPrivateAsn ) || stPrivateAsn.iTagClass != ASN_APPLICATION ||
		 stPrivateAsn.iTagValue != KRB_PRIV_MESSAGE || !findContextNode( &stPrivateAsn, 3, &pCipherNode ) ||
		 asnGetEncryptedData( &pCipherNode->pSubElements[0], &stCipher ) || stCipher.iEtype != pSubkey->iKeyType ||
		 kerberosDecrypt( stCipher.pbCipher, stCipher.cbCipher, pSubkey, KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART,
						  &pbPlaintext, &cbPlaintext ) ||
		 asnDecode( pbPlaintext, cbPlaintext, &stPlainAsn ) || stPlainAsn.iTagClass != ASN_APPLICATION ||
		 stPlainAsn.iTagValue != KRB_ENC_PRIV_PART_MESSAGE || !findContextNode( &stPlainAsn, 0, &pDataNode ) ||
		 asnGetOctetString( &pDataNode->pSubElements[0], &pbResult, &cbResult ) || cbResult < 2 )
		goto Cleanup;
	*pusResult = readNetworkUshort( pbResult );
	bSuccess   = TRUE;

Cleanup:
	asnRelease( &stPrivateAsn );
	asnRelease( &stPlainAsn );
	asnRelease( &stErrorAsn );
	releaseEncryptedData( &stCipher );
	if ( pbPlaintext )
	{
		SecureZeroMemory( pbPlaintext, ( SIZE_T )cbPlaintext );
		VirtualFree( pbPlaintext, 0, MEM_RELEASE );
	}
	if ( pbResult )
	{
		SecureZeroMemory( pbResult, ( SIZE_T )cbResult );
		VirtualFree( pbResult, 0, MEM_RELEASE );
	}
	return bSuccess;
}

BOOL changePasswordRfc3244( KRB_CRED *pServiceCredential, PCSTR pszDc, PCSTR pszPassword, PUSHORT pusResult )
{
	KRB_CRED_INFO *pInfo;
	AP_REQ		   stApRequest	  = { 0 };
	ASN_ELEMENT	   stApRequestAsn = { 0 };
	ENCRYPTION_KEY stSubkey		  = { 0 };
	KERBEROS_TIME  stTime		  = { 0 };
	LONG		   lMicroseconds  = 0;
	UINT		   uiSequence	  = 0;
	PBYTE		   pbChangeData	  = NULL;
	INT			   cbChangeData	  = 0;
	PBYTE		   pbPrivatePart  = NULL;
	INT			   cbPrivatePart  = 0;
	PBYTE		   pbPrivate	  = NULL;
	INT			   cbPrivate	  = 0;
	PBYTE		   pbApRequest	  = NULL;
	INT			   cbApRequest	  = 0;
	PBYTE		   pbMessage	  = NULL;
	INT			   cbMessage	  = 0;
	PBYTE		   pbResponse	  = NULL;
	INT			   cbResponse	  = 0;
	BOOL		   bSuccess		  = FALSE;

	if ( pusResult )
		*pusResult = USHRT_MAX;
	if ( !pServiceCredential || !pszDc || !pszPassword || !pszPassword[0] || !pusResult ||
		 pServiceCredential->cTickets < 1 || !pServiceCredential->pTickets ||
		 pServiceCredential->stEncryptedPart.cTickets < 1 || !pServiceCredential->stEncryptedPart.pTicketInfo )
		goto Cleanup;
	pInfo = &pServiceCredential->stEncryptedPart.pTicketInfo[0];
	if ( pInfo->stClientName.cNames < 1 || !pInfo->stClientName.ppszNames || !pInfo->stClientName.ppszNames[0] ||
		 !pInfo->pszClientRealm || !pInfo->stKey.pbKey || pInfo->stKey.cbKey <= 0 )
		goto Cleanup;
	if ( !generateRandomKey( pInfo->stKey.iKeyType, &stSubkey ) || !generateSequenceNumber( &uiSequence ) ||
		 !getKerberosTime( 0, &stTime, &lMicroseconds ) )
		goto Cleanup;
	stApRequest.lProtocolVersion			   = KRB_PROTOCOL_VERSION;
	stApRequest.lMessageType				   = KERB_AP_REQ;
	stApRequest.uiApOptions					   = KRB_AP_OPTION_MUTUAL_REQUIRED;
	stApRequest.stTicket					   = pServiceCredential->pTickets[0];
	stApRequest.stKey						   = pInfo->stKey;
	stApRequest.iKeyUsage					   = KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR;
	stApRequest.stAuthenticator.lVersion	   = KRB_PROTOCOL_VERSION;
	stApRequest.stAuthenticator.stClientName   = pInfo->stClientName;
	stApRequest.stAuthenticator.lMicroseconds  = lMicroseconds;
	stApRequest.stAuthenticator.stClientTime   = stTime;
	stApRequest.stAuthenticator.bHasSubkey	   = TRUE;
	stApRequest.stAuthenticator.stSubkey	   = stSubkey;
	stApRequest.stAuthenticator.bHasSequence   = TRUE;
	stApRequest.stAuthenticator.uiSequence	   = uiSequence;
	stApRequest.stAuthenticator.pszClientRealm = stringClone( pInfo->pszClientRealm );
	if ( !stApRequest.stAuthenticator.pszClientRealm || asnBuildApRequest( &stApRequest, &stApRequestAsn ) ||
		 asnEncode( &stApRequestAsn, &pbApRequest, &cbApRequest ) ||
		 !encodeChangePasswdData( pszPassword, &pbChangeData, &cbChangeData ) ||
		 !encodeEncKrbPrivPart( pbChangeData, cbChangeData, lMicroseconds, uiSequence, &pbPrivatePart,
								&cbPrivatePart ) ||
		 !encodeKrbPriv( pbPrivatePart, cbPrivatePart, &stSubkey, &pbPrivate, &cbPrivate ) )
		goto Cleanup;
	if ( cbApRequest > USHRT_MAX || cbPrivate > USHRT_MAX ||
		 cbApRequest + cbPrivate + KRB_KPASSWD_HEADER_SIZE > USHRT_MAX )
		goto Cleanup;
	cbMessage = cbApRequest + cbPrivate + KRB_KPASSWD_HEADER_SIZE;
	pbMessage = memAlloc( ( SIZE_T )cbMessage );
	if ( !pbMessage )
		goto Cleanup;
	writeNetworkUshort( pbMessage, ( USHORT )cbMessage );
	writeNetworkUshort( pbMessage + 2, KRB_KPASSWD_VERSION );
	writeNetworkUshort( pbMessage + 4, ( USHORT )cbApRequest );
	memcpy( pbMessage + KRB_KPASSWD_HEADER_SIZE, pbApRequest, ( SIZE_T )cbApRequest );
	memcpy( pbMessage + KRB_KPASSWD_HEADER_SIZE + cbApRequest, pbPrivate, ( SIZE_T )cbPrivate );

	if ( !sendKerberosRequest( pszDc, KRB_KPASSWD_PORT, pbMessage, cbMessage, &pbResponse, &cbResponse ) ||
		 !parseKpasswdResponse( pbResponse, cbResponse, &stSubkey, pusResult ) )
		goto Cleanup;
	bSuccess = TRUE;

Cleanup:
	asnRelease( &stApRequestAsn );
	if ( stApRequest.stAuthenticator.pszClientRealm )
		VirtualFree( stApRequest.stAuthenticator.pszClientRealm, 0, MEM_RELEASE );
	releaseEncryptionKey( &stSubkey );
	if ( pbChangeData )
	{
		SecureZeroMemory( pbChangeData, ( SIZE_T )cbChangeData );
		VirtualFree( pbChangeData, 0, MEM_RELEASE );
	}
	if ( pbPrivatePart )
	{
		SecureZeroMemory( pbPrivatePart, ( SIZE_T )cbPrivatePart );
		VirtualFree( pbPrivatePart, 0, MEM_RELEASE );
	}
	if ( pbPrivate )
	{
		SecureZeroMemory( pbPrivate, ( SIZE_T )cbPrivate );
		VirtualFree( pbPrivate, 0, MEM_RELEASE );
	}
	if ( pbApRequest )
		VirtualFree( pbApRequest, 0, MEM_RELEASE );
	if ( pbMessage )
	{
		SecureZeroMemory( pbMessage, ( SIZE_T )cbMessage );
		VirtualFree( pbMessage, 0, MEM_RELEASE );
	}
	if ( pbResponse )
		VirtualFree( pbResponse, 0, MEM_RELEASE );
	return bSuccess;
}
