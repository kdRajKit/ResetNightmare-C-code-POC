/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        asn_format.c                                                                                         *
*   DESCRIPCION:   Construccion y formateo de estructuras ASN.1 empleadas por Kerberos.                                *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                      FORMATEO Y CONSTRUCCION ASN.1                                                   *
***********************************************************************************************************************/

static VOID formatKerberosTime( PCHAR pszBuffer, KERBEROS_TIME stTime )
{
	pszBuffer[0]  = ( CHAR )( '0' + ( ( stTime.iYear / 1000 ) % 10 ) );
	pszBuffer[1]  = ( CHAR )( '0' + ( ( stTime.iYear / 100 ) % 10 ) );
	pszBuffer[2]  = ( CHAR )( '0' + ( ( stTime.iYear / 10 ) % 10 ) );
	pszBuffer[3]  = ( CHAR )( '0' + ( stTime.iYear % 10 ) );
	pszBuffer[4]  = ( CHAR )( '0' + ( ( stTime.iMonth / 10 ) % 10 ) );
	pszBuffer[5]  = ( CHAR )( '0' + ( stTime.iMonth % 10 ) );
	pszBuffer[6]  = ( CHAR )( '0' + ( ( stTime.iDay / 10 ) % 10 ) );
	pszBuffer[7]  = ( CHAR )( '0' + ( stTime.iDay % 10 ) );
	pszBuffer[8]  = ( CHAR )( '0' + ( ( stTime.iHour / 10 ) % 10 ) );
	pszBuffer[9]  = ( CHAR )( '0' + ( stTime.iHour % 10 ) );
	pszBuffer[10] = ( CHAR )( '0' + ( ( stTime.iMinute / 10 ) % 10 ) );
	pszBuffer[11] = ( CHAR )( '0' + ( stTime.iMinute % 10 ) );
	pszBuffer[12] = ( CHAR )( '0' + ( ( stTime.iSecond / 10 ) % 10 ) );
	pszBuffer[13] = ( CHAR )( '0' + ( stTime.iSecond % 10 ) );
	pszBuffer[14] = 'Z';
	pszBuffer[15] = '\0';
}

BOOL getKerberosTime( UINT uiSecondsFromNow, KERBEROS_TIME *pTime, PLONG plMicroseconds )
{
	SYSTEMTIME	   stSystemTime;
	FILETIME	   stFileTime;
	ULARGE_INTEGER uliTime;
	ULONGLONG	   ullDelta = ( ULONGLONG )uiSecondsFromNow * 10000000ULL;

	if ( !pTime )
		return FALSE;
	ZeroMemory( pTime, sizeof( *pTime ) );
	GetSystemTime( &stSystemTime );
	if ( plMicroseconds )
		*plMicroseconds = ( LONG )stSystemTime.wMilliseconds * 1000;
	if ( !SystemTimeToFileTime( &stSystemTime, &stFileTime ) )
		return FALSE;
	uliTime.LowPart	 = stFileTime.dwLowDateTime;
	uliTime.HighPart = stFileTime.dwHighDateTime;
	if ( uliTime.QuadPart > ~( ULONGLONG )0 - ullDelta )
		return FALSE;
	uliTime.QuadPart += ullDelta;
	stFileTime.dwLowDateTime  = uliTime.LowPart;
	stFileTime.dwHighDateTime = uliTime.HighPart;
	if ( !FileTimeToSystemTime( &stFileTime, &stSystemTime ) )
		return FALSE;
	pTime->bIsSet  = TRUE;
	pTime->iYear   = stSystemTime.wYear;
	pTime->iMonth  = stSystemTime.wMonth;
	pTime->iDay	   = stSystemTime.wDay;
	pTime->iHour   = stSystemTime.wHour;
	pTime->iMinute = stSystemTime.wMinute;
	pTime->iSecond = stSystemTime.wSecond;
	return TRUE;
}

static VOID flagsToBytes( UINT32 uiOptions, PBYTE pbOptions )
{
	UINT32 uiNetworkOptions = htonl( uiOptions );

	memcpy( pbOptions, &uiNetworkOptions, sizeof( uiNetworkOptions ) );
}

static BOOL asnMakePrimitive( INT iTagClass, INT iTagValue, const BYTE *pbValue, INT cbData, ASN_ELEMENT *pElement )
{
	if ( !pElement || iTagClass < 0 || iTagClass > 3 || iTagValue < 0 || cbData < 0 || ( cbData > 0 && !pbValue ) )
		return TRUE;
	ZeroMemory( pElement, sizeof( *pElement ) );
	pElement->cbObjectCapacity = cbData;
	if ( cbData > 0 )
	{
		pElement->pbObject = memClone( pbValue, ( SIZE_T )cbData );
		if ( !pElement->pbObject )
			return TRUE;
		pElement->bOwnsObject = TRUE;
	}

	pElement->iObjectOffset		= 0;
	pElement->cbObject			= -1;
	pElement->iValueOffset		= 0;
	pElement->cbValue			= cbData;
	pElement->bHasEncodedHeader = FALSE;
	pElement->bConstructed		= FALSE;
	pElement->iTagClass			= iTagClass;
	pElement->iTagValue			= iTagValue;
	pElement->pSubElements		= NULL;
	pElement->cSubElements		= 0;
	return FALSE;
}

static BOOL asnMakeInteger( LONGLONG llValue, ASN_ELEMENT *pOutput )
{
	BYTE	  abyValue[sizeof( LONGLONG )];
	INT		  cBytes   = ( INT )ARRAYSIZE( abyValue );
	INT		  iOffset  = 0;
	ULONGLONG ullValue = ( ULONGLONG )llValue;

	for ( INT iByte = cBytes - 1; iByte >= 0; iByte-- )
	{
		abyValue[iByte] = ( BYTE )ullValue;
		ullValue >>= 8;
	}
	while ( iOffset < cBytes - 1 && ( ( abyValue[iOffset] == 0x00 && ( abyValue[iOffset + 1] & 0x80 ) == 0 ) ||
									  ( abyValue[iOffset] == 0xFF && ( abyValue[iOffset + 1] & 0x80 ) != 0 ) ) )
		iOffset++;

	return asnMakePrimitive( ASN_UNIVERSAL, ASN_INTEGER, abyValue + iOffset, cBytes - iOffset, pOutput );
}

static BOOL asnMakeConstructed( INT iTagClass, INT iTagValue, ASN_ELEMENT *pSubElements, INT cSubElements,
								ASN_ELEMENT *pElement )
{
	if ( !pElement )
		return TRUE;
	if ( iTagClass < 0 || iTagClass > 3 || iTagValue < 0 || cSubElements < 0 || cSubElements > ASN_MAX_SUBELEMENTS ||
		 ( cSubElements > 0 && !pSubElements ) || ( SIZE_T )cSubElements > SIZE_MAX / sizeof( ASN_ELEMENT ) )
		return TRUE;
	ZeroMemory( pElement, sizeof( *pElement ) );
	pElement->pbObject			= NULL;
	pElement->bConstructed		= TRUE;
	pElement->cbObjectCapacity	= 0;
	pElement->iObjectOffset		= 0;
	pElement->cbObject			= -1;
	pElement->iValueOffset		= 0;
	pElement->cbValue			= -1;
	pElement->bHasEncodedHeader = FALSE;
	pElement->iTagClass			= iTagClass;
	pElement->iTagValue			= iTagValue;
	if ( cSubElements == 0 )
	{
		pElement->cSubElements = 0;
		pElement->pSubElements = NULL;
	}
	else
	{
		pElement->cSubElements = cSubElements;
		pElement->pSubElements = memAlloc( ( SIZE_T )cSubElements * sizeof( ASN_ELEMENT ) );
		if ( !pElement->pSubElements )
		{
			return TRUE;
		}
		for ( INT iSubElement = 0; iSubElement < cSubElements; iSubElement++ )
		{
			pElement->pSubElements[iSubElement] = pSubElements[iSubElement];
			ZeroMemory( &pSubElements[iSubElement], sizeof( pSubElements[iSubElement] ) );
		}
	}
	return FALSE;
}

BOOL asnMakeSequence( ASN_ELEMENT *pSubElements, INT cSubElements, ASN_ELEMENT *pElement )
{
	return asnMakeConstructed( ASN_UNIVERSAL, ASN_SEQUENCE, pSubElements, cSubElements, pElement );
}

BOOL asnMakeExplicit( INT iTagClass, INT iTagValue, ASN_ELEMENT *pValue, ASN_ELEMENT *pElement )
{
	if ( !pValue )
		return TRUE;
	return asnMakeConstructed( iTagClass, iTagValue, pValue, 1, pElement );
}

static BOOL asnMakeOctetString( const BYTE *pbBuffer, INT cbData, ASN_ELEMENT *pElement )
{
	return asnMakePrimitive( ASN_UNIVERSAL, ASN_OCTET_STRING, pbBuffer, cbData, pElement );
}

static BOOL asnMakeString( INT iType, PCSTR pszValue, ASN_ELEMENT *pElement )
{
	SIZE_T cchValue;

	if ( !pszValue )
		return TRUE;
	cchValue = strlen( pszValue );
	if ( cchValue > INT_MAX )
		return TRUE;
	return asnMakePrimitive( ASN_UNIVERSAL, iType, ( const BYTE * )pszValue, ( INT )cchValue, pElement );
}

BOOL asnPackInteger( INT iTagValue, INT iValue, ASN_ELEMENT *pContext )
{
	ASN_ELEMENT stInteger = { 0 };
	BOOL		bFailure;

	bFailure = asnMakeInteger( iValue, &stInteger ) || asnMakeExplicit( ASN_CONTEXT, iTagValue, &stInteger, pContext );
	asnRelease( &stInteger );
	return bFailure;
}

BOOL asnPackUnsignedInteger( INT iTagValue, UINT uiValue, ASN_ELEMENT *pContext )
{
	ASN_ELEMENT stInteger = { 0 };
	BOOL		bFailure;

	bFailure = asnMakeInteger( ( LONGLONG )uiValue, &stInteger ) ||
			   asnMakeExplicit( ASN_CONTEXT, iTagValue, &stInteger, pContext );
	asnRelease( &stInteger );
	return bFailure;
}

static BOOL packString( INT iTagValue, INT iType, PCSTR pszValue, ASN_ELEMENT *pContext )
{
	ASN_ELEMENT stString = { 0 };
	BOOL		bFailure;

	bFailure =
		asnMakeString( iType, pszValue, &stString ) || asnMakeExplicit( ASN_CONTEXT, iTagValue, &stString, pContext );
	asnRelease( &stString );
	return bFailure;
}

static BOOL packBitString( INT iTagValue, const BYTE *pbValue, INT cbValue, ASN_ELEMENT *pContext )
{
	BYTE	   *pbBitString = NULL;
	ASN_ELEMENT stBitString = { 0 };
	BOOL		bFailure;

	if ( cbValue < 0 || cbValue == INT_MAX || ( !pbValue && cbValue > 0 ) || !pContext )
		return TRUE;
	pbBitString = memAlloc( ( SIZE_T )cbValue + 1 );
	if ( !pbBitString )
		return TRUE;
	pbBitString[0] = 0;
	if ( cbValue > 0 )
		memcpy( pbBitString + 1, pbValue, ( SIZE_T )cbValue );
	bFailure = asnMakePrimitive( ASN_UNIVERSAL, ASN_BIT_STRING, pbBitString, cbValue + 1, &stBitString );
	VirtualFree( pbBitString, 0, MEM_RELEASE );
	if ( !bFailure )
		bFailure = asnMakeExplicit( ASN_CONTEXT, iTagValue, &stBitString, pContext );
	asnRelease( &stBitString );
	return bFailure;
}

BOOL asnPackOctetString( INT iTagValue, const BYTE *pbData, INT cbData, ASN_ELEMENT *pContext )
{
	ASN_ELEMENT stBlock = { 0 };
	BOOL		bFailure;

	bFailure = asnMakeOctetString( pbData, cbData, &stBlock ) ||
			   asnMakeExplicit( ASN_CONTEXT, iTagValue, &stBlock, pContext );
	asnRelease( &stBlock );
	return bFailure;
}

BOOL asnCreateEncryptedTimestampPaData( const ENCRYPTION_KEY *pKey, PA_DATA *pPaData )
{
	CHAR			szTime[18];
	KERBEROS_TIME	stTime;
	ASN_ELEMENT		stTimestamp	   = { 0 };
	ASN_ELEMENT		stSequence	   = { 0 };
	PENCRYPTED_DATA pEncryptedData = NULL;
	PBYTE			pbPlaintext	   = NULL;
	PBYTE			pbCiphertext   = NULL;
	INT				cbPlaintext	   = 0;
	INT				cbCiphertext   = 0;
	BOOL			bFailure	   = TRUE;

	if ( !pPaData )
		goto Cleanup;
	ZeroMemory( pPaData, sizeof( *pPaData ) );
	if ( !pKey || !pKey->pbKey || pKey->cbKey <= 0 )
		goto Cleanup;
	if ( !getKerberosTime( 0, &stTime, NULL ) )
		goto Cleanup;
	formatKerberosTime( szTime, stTime );
	if ( packString( 0, ASN_GENERALIZED_TIME, szTime, &stTimestamp ) ||
		 asnMakeSequence( &stTimestamp, 1, &stSequence ) || asnEncode( &stSequence, &pbPlaintext, &cbPlaintext ) ||
		 kerberosEncrypt( pbPlaintext, cbPlaintext, pKey, KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pbCiphertext,
						  &cbCiphertext ) )
		goto Cleanup;
	pEncryptedData = memAlloc( sizeof( *pEncryptedData ) );
	if ( !pEncryptedData )
		goto Cleanup;
	pEncryptedData->iEtype	 = pKey->iKeyType;
	pEncryptedData->pbCipher = pbCiphertext;
	pEncryptedData->cbCipher = cbCiphertext;
	pPaData->uiType			 = PADATA_ENC_TIMESTAMP;
	pPaData->pvValue		 = pEncryptedData;
	pbCiphertext			 = NULL;
	pEncryptedData			 = NULL;
	bFailure				 = FALSE;

Cleanup:
	asnRelease( &stTimestamp );
	asnRelease( &stSequence );
	if ( pbPlaintext )
	{
		SecureZeroMemory( pbPlaintext, ( SIZE_T )cbPlaintext );
		VirtualFree( pbPlaintext, 0, MEM_RELEASE );
	}
	if ( pbCiphertext )
	{
		SecureZeroMemory( pbCiphertext, ( SIZE_T )cbCiphertext );
		VirtualFree( pbCiphertext, 0, MEM_RELEASE );
	}
	if ( pEncryptedData )
		VirtualFree( pEncryptedData, 0, MEM_RELEASE );
	return bFailure;
}

static BOOL asnBuildPrincipalName( PRINCIPAL_NAME *pName, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT	 astFields[2] = { 0 };
	ASN_ELEMENT	 stNames	  = { 0 };
	PASN_ELEMENT pNames		  = NULL;
	BOOL		 bFailure	  = TRUE;

	if ( !pName || !pOutput || pName->cNames <= 0 || !pName->ppszNames ||
		 ( SIZE_T )pName->cNames > SIZE_MAX / sizeof( ASN_ELEMENT ) ||
		 asnPackInteger( 0, pName->lNameType, &astFields[0] ) )
		goto Cleanup;
	pNames = memAlloc( sizeof( ASN_ELEMENT ) * ( SIZE_T )pName->cNames );
	if ( !pNames )
		goto Cleanup;
	for ( INT iName = 0; iName < pName->cNames; iName++ )
	{
		if ( !pName->ppszNames[iName] || asnMakeString( ASN_GENERAL_STRING, pName->ppszNames[iName], &pNames[iName] ) )
			goto Cleanup;
	}
	if ( asnMakeSequence( pNames, pName->cNames, &stNames ) ||
		 asnMakeExplicit( ASN_CONTEXT, 1, &stNames, &astFields[1] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stNames );
	if ( pNames )
	{
		for ( INT iName = 0; iName < pName->cNames; iName++ )
			asnRelease( &pNames[iName] );
		VirtualFree( pNames, 0, MEM_RELEASE );
	}
	return bFailure;
}

BOOL asnBuildEncryptedData( ENCRYPTED_DATA *pData, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT astFields[3] = { 0 };
	INT			cFields		 = 0;
	BOOL		bFailure;

	if ( !pData || !pOutput || !pData->pbCipher || pData->cbCipher <= 0 )
		return TRUE;
	bFailure = asnPackInteger( 0, pData->iEtype, &astFields[cFields++] );
	if ( !bFailure && pData->uiKvno != 0 )
		bFailure = asnPackUnsignedInteger( 1, pData->uiKvno, &astFields[cFields++] );
	if ( !bFailure )
		bFailure = asnPackOctetString( 2, pData->pbCipher, pData->cbCipher, &astFields[cFields++] );
	if ( !bFailure )
		bFailure = asnMakeSequence( astFields, cFields, pOutput );
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	return bFailure;
}

static BOOL asnBuildEncryptionKey( ENCRYPTION_KEY *pKey, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT astFields[2] = { 0 };
	BOOL		bFailure;

	if ( !pKey || !pOutput || !pKey->pbKey || pKey->cbKey <= 0 )
		return TRUE;
	bFailure = asnPackInteger( 0, pKey->iKeyType, &astFields[0] ) ||
			   asnPackOctetString( 1, pKey->pbKey, pKey->cbKey, &astFields[1] ) ||
			   asnMakeSequence( astFields, ARRAYSIZE( astFields ), pOutput );
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	return bFailure;
}

static BOOL asnBuildTicket( KERBEROS_TICKET *pTicket, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT astFields[4] = { 0 };
	ASN_ELEMENT stName		 = { 0 };
	ASN_ELEMENT stEncrypted	 = { 0 };
	ASN_ELEMENT stBody		 = { 0 };
	BOOL		bFailure	 = TRUE;

	if ( !pTicket || !pOutput || pTicket->iTicketVersion != KRB_PROTOCOL_VERSION || !pTicket->pszRealm ||
		 asnPackInteger( 0, pTicket->iTicketVersion, &astFields[0] ) ||
		 packString( 1, ASN_GENERAL_STRING, pTicket->pszRealm, &astFields[1] ) ||
		 asnBuildPrincipalName( &pTicket->stServiceName, &stName ) ||
		 asnMakeExplicit( ASN_CONTEXT, 2, &stName, &astFields[2] ) ||
		 asnBuildEncryptedData( &pTicket->stEncryptedPart, &stEncrypted ) ||
		 asnMakeExplicit( ASN_CONTEXT, 3, &stEncrypted, &astFields[3] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KRB_TICKET_MESSAGE, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stName );
	asnRelease( &stEncrypted );
	asnRelease( &stBody );
	return bFailure;
}

static BOOL asnBuildKdcRequestBody( KDC_REQUEST_BODY *pRequestBody, ASN_ELEMENT *pOutput )
{
	BYTE		  abyOptions[sizeof( UINT32 )];
	CHAR		  szTime[18];
	KERBEROS_TIME stExpiration;
	ASN_ELEMENT	  astFields[7] = { 0 };
	ASN_ELEMENT	  stName	   = { 0 };
	ASN_ELEMENT	  stEtype	   = { 0 };
	ASN_ELEMENT	  stEtypes	   = { 0 };
	INT			  cFields	   = 0;
	BOOL		  bFailure	   = TRUE;

	if ( !pRequestBody || !pOutput || !pRequestBody->pszRealm || pRequestBody->uiLifetime == 0 ||
		 pRequestBody->iEtype < 0 )
		goto Cleanup;
	flagsToBytes( pRequestBody->uiOptions, abyOptions );
	if ( packBitString( 0, abyOptions, sizeof( abyOptions ), &astFields[cFields++] ) )
		goto Cleanup;

	if ( pRequestBody->stClientName.cNames > 0 )
	{
		if ( asnBuildPrincipalName( &pRequestBody->stClientName, &stName ) ||
			 asnMakeExplicit( ASN_CONTEXT, 1, &stName, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( packString( 2, ASN_GENERAL_STRING, pRequestBody->pszRealm, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pRequestBody->stServiceName.cNames > 0 )
	{
		if ( asnBuildPrincipalName( &pRequestBody->stServiceName, &stName ) ||
			 asnMakeExplicit( ASN_CONTEXT, 3, &stName, &astFields[cFields++] ) )
			goto Cleanup;
	}

	if ( !getKerberosTime( pRequestBody->uiLifetime, &stExpiration, NULL ) )
		goto Cleanup;
	formatKerberosTime( szTime, stExpiration );
	if ( packString( 5, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
		goto Cleanup;
	if ( asnPackUnsignedInteger( 7, pRequestBody->uiNonce, &astFields[cFields++] ) )
		goto Cleanup;

	if ( asnMakeInteger( pRequestBody->iEtype, &stEtype ) || asnMakeSequence( &stEtype, 1, &stEtypes ) ||
		 asnMakeExplicit( ASN_CONTEXT, 8, &stEtypes, &astFields[cFields++] ) ||
		 asnMakeSequence( astFields, cFields, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stName );
	asnRelease( &stEtype );
	asnRelease( &stEtypes );
	return bFailure;
}

static BOOL asnBuildAuthenticator( KERBEROS_AUTHENTICATOR *pAuthenticator, ASN_ELEMENT *pOutput )
{
	CHAR		szTime[18];
	ASN_ELEMENT astFields[7] = { 0 };
	ASN_ELEMENT stValue		 = { 0 };
	ASN_ELEMENT stBody		 = { 0 };
	INT			cFields		 = 0;
	BOOL		bFailure	 = TRUE;

	if ( !pAuthenticator || !pOutput || pAuthenticator->lVersion != KRB_PROTOCOL_VERSION ||
		 !pAuthenticator->pszClientRealm || !pAuthenticator->stClientTime.bIsSet ||
		 pAuthenticator->lMicroseconds < 0 || pAuthenticator->lMicroseconds > 999999 ||
		 asnPackInteger( 0, pAuthenticator->lVersion, &astFields[cFields++] ) ||
		 packString( 1, ASN_GENERAL_STRING, pAuthenticator->pszClientRealm, &astFields[cFields++] ) ||
		 asnBuildPrincipalName( &pAuthenticator->stClientName, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 2, &stValue, &astFields[cFields++] ) ||
		 asnPackInteger( 4, pAuthenticator->lMicroseconds, &astFields[cFields++] ) )
		goto Cleanup;
	formatKerberosTime( szTime, pAuthenticator->stClientTime );
	if ( packString( 5, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pAuthenticator->bHasSubkey && ( asnBuildEncryptionKey( &pAuthenticator->stSubkey, &stValue ) ||
										 asnMakeExplicit( ASN_CONTEXT, 6, &stValue, &astFields[cFields++] ) ) )
		goto Cleanup;
	if ( pAuthenticator->bHasSequence &&
		 asnPackUnsignedInteger( 7, pAuthenticator->uiSequence, &astFields[cFields++] ) )
		goto Cleanup;
	if ( asnMakeSequence( astFields, cFields, &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KRB_AUTHENTICATOR_MESSAGE, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	asnRelease( &stBody );
	return bFailure;
}

BOOL asnBuildApRequest( AP_REQ *pRequest, ASN_ELEMENT *pOutput )
{
	BYTE		   abyOptions[sizeof( UINT32 )];
	ASN_ELEMENT	   astFields[5]	   = { 0 };
	ASN_ELEMENT	   stValue		   = { 0 };
	ASN_ELEMENT	   stAuthenticator = { 0 };
	ASN_ELEMENT	   stBody		   = { 0 };
	ENCRYPTED_DATA stEncrypted	   = { 0 };
	PBYTE		   pbPlaintext	   = NULL;
	PBYTE		   pbCiphertext	   = NULL;
	INT			   cbPlaintext	   = 0;
	INT			   cbCiphertext	   = 0;
	BOOL		   bFailure		   = TRUE;

	if ( !pRequest || !pOutput || pRequest->lProtocolVersion != KRB_PROTOCOL_VERSION ||
		 pRequest->lMessageType != KERB_AP_REQ || !pRequest->stKey.pbKey || pRequest->stKey.cbKey <= 0 ||
		 asnPackInteger( 0, pRequest->lProtocolVersion, &astFields[0] ) ||
		 asnPackInteger( 1, pRequest->lMessageType, &astFields[1] ) )
		goto Cleanup;
	flagsToBytes( pRequest->uiApOptions, abyOptions );
	if ( packBitString( 2, abyOptions, sizeof( abyOptions ), &astFields[2] ) ||
		 asnBuildTicket( &pRequest->stTicket, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 3, &stValue, &astFields[3] ) ||
		 asnBuildAuthenticator( &pRequest->stAuthenticator, &stAuthenticator ) ||
		 asnEncode( &stAuthenticator, &pbPlaintext, &cbPlaintext ) ||
		 kerberosEncrypt( pbPlaintext, cbPlaintext, &pRequest->stKey, pRequest->iKeyUsage, &pbCiphertext,
						  &cbCiphertext ) )
		goto Cleanup;
	stEncrypted.iEtype	 = pRequest->stKey.iKeyType;
	stEncrypted.pbCipher = pbCiphertext;
	stEncrypted.cbCipher = cbCiphertext;
	if ( asnBuildEncryptedData( &stEncrypted, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 4, &stValue, &astFields[4] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KERB_AP_REQ, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	asnRelease( &stAuthenticator );
	asnRelease( &stBody );
	if ( pbPlaintext )
	{
		SecureZeroMemory( pbPlaintext, ( SIZE_T )cbPlaintext );
		VirtualFree( pbPlaintext, 0, MEM_RELEASE );
	}
	if ( pbCiphertext )
	{
		SecureZeroMemory( pbCiphertext, ( SIZE_T )cbCiphertext );
		VirtualFree( pbCiphertext, 0, MEM_RELEASE );
	}
	return bFailure;
}

static BOOL asnBuildPaData( PA_DATA stPaData, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT astFields[2] = { 0 };
	ASN_ELEMENT stValue      = { 0 };
	ASN_ELEMENT stBoolean    = { 0 };
	ASN_ELEMENT stPacField   = { 0 };
	PBYTE       pbValue      = NULL;
	INT         cbValue      = 0;
	BYTE        bBooleanValue;
	BOOL        bFailure     = TRUE;

	if ( !pOutput || !stPaData.pvValue || asnPackInteger( 1, ( INT )stPaData.uiType, &astFields[0] ) )
		goto Cleanup;
	if ( stPaData.uiType == PADATA_ENC_TIMESTAMP )
	{
		if ( asnBuildEncryptedData( stPaData.pvValue, &stValue ) )
			goto Cleanup;
	}
	else if ( stPaData.uiType == PADATA_PA_PAC_REQUEST )
	{
		bBooleanValue = ( BYTE )( ( PKERB_PA_PAC_REQUEST )stPaData.pvValue )->bIncludePac;
		if ( asnMakePrimitive( ASN_UNIVERSAL, ASN_BOOLEAN, &bBooleanValue, 1, &stBoolean ) ||
			 asnMakeExplicit( ASN_CONTEXT, 0, &stBoolean, &stPacField ) ||
			 asnMakeSequence( &stPacField, 1, &stValue ) )
			goto Cleanup;
	}
	else
	{
		goto Cleanup;
	}
	if ( asnEncode( &stValue, &pbValue, &cbValue ) ||
		 asnPackOctetString( 2, pbValue, cbValue, &astFields[1] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	asnRelease( &stBoolean );
	asnRelease( &stPacField );
	if ( pbValue )
		VirtualFree( pbValue, 0, MEM_RELEASE );
	return bFailure;
}

static BOOL asnBuildKrbCredInfo( KRB_CRED_INFO *pCredentialInfo, ASN_ELEMENT *pOutput )
{
	BYTE		abyFlags[sizeof( UINT32 )];
	CHAR		szTime[18];
	ASN_ELEMENT astFields[10] = { 0 };
	ASN_ELEMENT stValue		  = { 0 };
	INT			cFields		  = 0;
	BOOL		bFailure	  = TRUE;

	if ( !pCredentialInfo || !pOutput || asnBuildEncryptionKey( &pCredentialInfo->stKey, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 0, &stValue, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pCredentialInfo->pszClientRealm &&
		 packString( 1, ASN_GENERAL_STRING, pCredentialInfo->pszClientRealm, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pCredentialInfo->stClientName.cNames > 0 &&
		 ( asnBuildPrincipalName( &pCredentialInfo->stClientName, &stValue ) ||
		   asnMakeExplicit( ASN_CONTEXT, 2, &stValue, &astFields[cFields++] ) ) )
		goto Cleanup;
	flagsToBytes( pCredentialInfo->uiFlags, abyFlags );
	if ( packBitString( 3, abyFlags, sizeof( abyFlags ), &astFields[cFields++] ) )
		goto Cleanup;
	if ( pCredentialInfo->stAuthTime.bIsSet )
	{
		formatKerberosTime( szTime, pCredentialInfo->stAuthTime );
		if ( packString( 4, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( pCredentialInfo->stStartTime.bIsSet )
	{
		formatKerberosTime( szTime, pCredentialInfo->stStartTime );
		if ( packString( 5, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( pCredentialInfo->stEndTime.bIsSet )
	{
		formatKerberosTime( szTime, pCredentialInfo->stEndTime );
		if ( packString( 6, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( pCredentialInfo->stRenewUntil.bIsSet )
	{
		formatKerberosTime( szTime, pCredentialInfo->stRenewUntil );
		if ( packString( 7, ASN_GENERALIZED_TIME, szTime, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( pCredentialInfo->pszServiceRealm &&
		 packString( 8, ASN_GENERAL_STRING, pCredentialInfo->pszServiceRealm, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pCredentialInfo->stServiceName.cNames > 0 &&
		 ( asnBuildPrincipalName( &pCredentialInfo->stServiceName, &stValue ) ||
		   asnMakeExplicit( ASN_CONTEXT, 9, &stValue, &astFields[cFields++] ) ) )
		goto Cleanup;
	if ( asnMakeSequence( astFields, cFields, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	return bFailure;
}

static BOOL asnBuildEncKrbCredPart( ENC_KRB_CRED_PART *pCredentialPart, ASN_ELEMENT *pOutput )
{
	PASN_ELEMENT pastTicketInfo = NULL;
	ASN_ELEMENT	 stInfoList		= { 0 };
	ASN_ELEMENT	 stContext		= { 0 };
	ASN_ELEMENT	 stBody			= { 0 };
	BOOL		 bFailure		= TRUE;

	if ( !pCredentialPart || !pOutput || pCredentialPart->cTickets < 1 || !pCredentialPart->pTicketInfo ||
		 ( SIZE_T )pCredentialPart->cTickets > SIZE_MAX / sizeof( ASN_ELEMENT ) )
		goto Cleanup;
	pastTicketInfo = memAlloc( sizeof( ASN_ELEMENT ) * ( SIZE_T )pCredentialPart->cTickets );
	if ( !pastTicketInfo )
		goto Cleanup;
	for ( INT iTicket = 0; iTicket < pCredentialPart->cTickets; iTicket++ )
	{
		if ( asnBuildKrbCredInfo( &pCredentialPart->pTicketInfo[iTicket], &pastTicketInfo[iTicket] ) )
			goto Cleanup;
	}
	if ( asnMakeSequence( pastTicketInfo, pCredentialPart->cTickets, &stInfoList ) ||
		 asnMakeExplicit( ASN_CONTEXT, 0, &stInfoList, &stContext ) || asnMakeSequence( &stContext, 1, &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KRB_ENC_CRED_PART_MESSAGE, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	asnRelease( &stInfoList );
	asnRelease( &stContext );
	asnRelease( &stBody );
	if ( pastTicketInfo )
	{
		for ( INT iTicket = 0; iTicket < pCredentialPart->cTickets; iTicket++ )
			asnRelease( &pastTicketInfo[iTicket] );
		VirtualFree( pastTicketInfo, 0, MEM_RELEASE );
	}
	return bFailure;
}

BOOL asnBuildKrbCredential( KRB_CRED *pCredential, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT	   astFields[4]		= { 0 };
	PASN_ELEMENT   pastTickets		= NULL;
	ASN_ELEMENT	   stTicketList		= { 0 };
	ASN_ELEMENT	   stEncodedPart	= { 0 };
	ASN_ELEMENT	   stEncryptedValue = { 0 };
	ASN_ELEMENT	   stBody			= { 0 };
	ENCRYPTED_DATA stEncrypted		= { 0 };
	PBYTE		   pbEncodedPart	= NULL;
	INT			   cbEncodedPart	= 0;
	BOOL		   bFailure			= TRUE;

	if ( !pCredential || !pOutput || pCredential->lProtocolVersion != KRB_PROTOCOL_VERSION ||
		 pCredential->lMessageType != KERB_CRED || pCredential->cTickets < 1 || !pCredential->pTickets ||
		 pCredential->stEncryptedPart.cTickets != pCredential->cTickets || !pCredential->stEncryptedPart.pTicketInfo ||
		 ( SIZE_T )pCredential->cTickets > SIZE_MAX / sizeof( ASN_ELEMENT ) ||
		 asnPackInteger( 0, pCredential->lProtocolVersion, &astFields[0] ) ||
		 asnPackInteger( 1, pCredential->lMessageType, &astFields[1] ) )
		goto Cleanup;
	pastTickets = memAlloc( sizeof( ASN_ELEMENT ) * ( SIZE_T )pCredential->cTickets );
	if ( !pastTickets )
		goto Cleanup;
	for ( INT iTicket = 0; iTicket < pCredential->cTickets; iTicket++ )
	{
		if ( asnBuildTicket( &pCredential->pTickets[iTicket], &pastTickets[iTicket] ) )
			goto Cleanup;
	}
	if ( asnMakeSequence( pastTickets, pCredential->cTickets, &stTicketList ) ||
		 asnMakeExplicit( ASN_CONTEXT, 2, &stTicketList, &astFields[2] ) ||
		 asnBuildEncKrbCredPart( &pCredential->stEncryptedPart, &stEncodedPart ) ||
		 asnEncode( &stEncodedPart, &pbEncodedPart, &cbEncodedPart ) )
		goto Cleanup;
	stEncrypted.iEtype	 = 0;
	stEncrypted.pbCipher = pbEncodedPart;
	stEncrypted.cbCipher = cbEncodedPart;
	if ( asnBuildEncryptedData( &stEncrypted, &stEncryptedValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 3, &stEncryptedValue, &astFields[3] ) ||
		 asnMakeSequence( astFields, ARRAYSIZE( astFields ), &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KERB_CRED, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stTicketList );
	asnRelease( &stEncodedPart );
	asnRelease( &stEncryptedValue );
	asnRelease( &stBody );
	if ( pastTickets )
	{
		for ( INT iTicket = 0; iTicket < pCredential->cTickets; iTicket++ )
			asnRelease( &pastTickets[iTicket] );
		VirtualFree( pastTickets, 0, MEM_RELEASE );
	}
	if ( pbEncodedPart )
	{
		SecureZeroMemory( pbEncodedPart, ( SIZE_T )cbEncodedPart );
		VirtualFree( pbEncodedPart, 0, MEM_RELEASE );
	}
	return bFailure;
}

BOOL asnBuildAsRequest( AS_REQ *pRequest, ASN_ELEMENT *pOutput )
{
	ASN_ELEMENT	 astFields[4] = { 0 };
	ASN_ELEMENT	 stValue	  = { 0 };
	ASN_ELEMENT	 stBody		  = { 0 };
	PASN_ELEMENT pPaElements  = NULL;
	INT			 cFields	  = 0;
	BOOL		 bFailure	  = TRUE;

	if ( !pRequest || !pOutput || pRequest->lProtocolVersion != KRB_PROTOCOL_VERSION ||
		 pRequest->lMessageType != KERB_AS_REQ || pRequest->cPaData < 0 ||
		 ( pRequest->cPaData > 0 && !pRequest->pPaData ) ||
		 ( SIZE_T )pRequest->cPaData > SIZE_MAX / sizeof( ASN_ELEMENT ) ||
		 asnPackInteger( 1, pRequest->lProtocolVersion, &astFields[cFields++] ) ||
		 asnPackInteger( 2, pRequest->lMessageType, &astFields[cFields++] ) )
		goto Cleanup;
	if ( pRequest->cPaData > 0 )
	{
		pPaElements = memAlloc( sizeof( ASN_ELEMENT ) * ( SIZE_T )pRequest->cPaData );
		if ( !pPaElements )
			goto Cleanup;
		for ( INT iPaData = 0; iPaData < pRequest->cPaData; iPaData++ )
		{
			if ( asnBuildPaData( pRequest->pPaData[iPaData], &pPaElements[iPaData] ) )
				goto Cleanup;
		}
		if ( asnMakeSequence( pPaElements, pRequest->cPaData, &stValue ) ||
			 asnMakeExplicit( ASN_CONTEXT, 3, &stValue, &astFields[cFields++] ) )
			goto Cleanup;
	}
	if ( asnBuildKdcRequestBody( &pRequest->stRequestBody, &stValue ) ||
		 asnMakeExplicit( ASN_CONTEXT, 4, &stValue, &astFields[cFields++] ) ||
		 asnMakeSequence( astFields, cFields, &stBody ) ||
		 asnMakeExplicit( ASN_APPLICATION, KERB_AS_REQ, &stBody, pOutput ) )
		goto Cleanup;
	bFailure = FALSE;

Cleanup:
	for ( SIZE_T iField = 0; iField < ARRAYSIZE( astFields ); iField++ )
		asnRelease( &astFields[iField] );
	asnRelease( &stValue );
	asnRelease( &stBody );
	if ( pPaElements )
	{
		for ( INT iPaData = 0; iPaData < pRequest->cPaData; iPaData++ )
			asnRelease( &pPaElements[iPaData] );
		VirtualFree( pPaElements, 0, MEM_RELEASE );
	}
	return bFailure;
}
