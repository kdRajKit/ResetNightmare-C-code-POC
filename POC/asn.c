/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        asn.c                                                                                                *
*   DESCRIPCION:   Codificacion y decodificacion ASN.1 empleada por Kerberos.                                          *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                          ESTRUCTURAS INTERNAS ASN.1                                                  *
***********************************************************************************************************************/

typedef struct _ASN_HEADER
{
	INT	 iTagClass;
	INT	 iTagValue;
	BOOL bConstructed;
	INT	 iValueOffset;
	INT	 cbValue;
	INT	 cbObject;
} ASN_HEADER, *PASN_HEADER;

/***********************************************************************************************************************
*                                              IMPLEMENTACION ASN.1                                                    *
***********************************************************************************************************************/

PVOID memAlloc( SIZE_T cbData )
{
	if ( cbData == 0 )
		return NULL;
	return VirtualAlloc( NULL, cbData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
}

PVOID memClone( const VOID *pvSource, SIZE_T cbData )
{
	PVOID pvCopy;

	if ( !pvSource || cbData == 0 )
		return NULL;
	pvCopy = memAlloc( cbData );
	if ( pvCopy )
		memcpy( pvCopy, pvSource, cbData );
	return pvCopy;
}

PCHAR stringClone( PCSTR pszSource )
{
	return pszSource ? memClone( pszSource, strlen( pszSource ) + 1 ) : NULL;
}

BOOL stringCopy( PCHAR pszDestination, SIZE_T cchDestination, PCSTR pszSource )
{
	SIZE_T cchSource;

	if ( !pszDestination || cchDestination == 0 || !pszSource )
		return FALSE;
	cchSource = strlen( pszSource );
	if ( cchSource >= cchDestination )
		return FALSE;
	memmove( pszDestination, pszSource, cchSource + 1 );
	return TRUE;
}

VOID releasePrincipalName( PRINCIPAL_NAME *pName )
{
	if ( !pName )
		return;
	if ( pName->ppszNames )
	{
		for ( INT iName = 0; iName < pName->cNames; iName++ )
		{
			if ( pName->ppszNames[iName] )
				VirtualFree( pName->ppszNames[iName], 0, MEM_RELEASE );
		}
		VirtualFree( pName->ppszNames, 0, MEM_RELEASE );
	}
	ZeroMemory( pName, sizeof( *pName ) );
}

VOID asnRelease( ASN_ELEMENT *pElement )
{
	if ( !pElement )
		return;
	if ( pElement->pSubElements )
	{
		for ( INT iElement = 0; iElement < pElement->cSubElements; iElement++ )
			asnRelease( &pElement->pSubElements[iElement] );
		VirtualFree( pElement->pSubElements, 0, MEM_RELEASE );
	}
	if ( pElement->bOwnsObject && pElement->pbObject )
	{
		if ( pElement->cbObjectCapacity > 0 )
			SecureZeroMemory( pElement->pbObject, ( SIZE_T )pElement->cbObjectCapacity );
		VirtualFree( pElement->pbObject, 0, MEM_RELEASE );
	}
	ZeroMemory( pElement, sizeof( *pElement ) );
}

static INT asnWriteElement( ASN_ELEMENT *pElement, BYTE *pbDestination, INT iDestinationOffset );

static INT asnValueLength( ASN_ELEMENT *pElement );

static INT asnEncodedComponentLength( INT iValue, INT iThreshold, INT cShift )
{
	INT cBytes = 1;

	if ( iValue < iThreshold )
		return 1;
	while ( iValue > 0 )
	{
		iValue >>= cShift;
		cBytes++;
	}
	return cBytes;
}

static INT asnEncodedLength( ASN_ELEMENT *pElement )
{
	INT cbTag;
	INT cbLength;
	INT cbValue;

	if ( !pElement || pElement->iTagClass < 0 || pElement->iTagClass > 3 || pElement->iTagValue < 0 )
		return -1;
	if ( pElement->cbObject < 0 )
	{
		cbValue = asnValueLength( pElement );
		if ( cbValue < 0 )
			return -1;
		cbTag	 = asnEncodedComponentLength( pElement->iTagValue, 0x1F, 7 );
		cbLength = asnEncodedComponentLength( cbValue, 0x80, 8 );
		if ( cbTag > INT_MAX - cbLength || cbTag + cbLength > INT_MAX - cbValue )
			return -1;
		pElement->cbObject = cbTag + cbLength + cbValue;
	}
	return pElement->cbObject;
}

static INT asnValueLength( ASN_ELEMENT *pElement )
{
	if ( !pElement )
		return -1;
	if ( pElement->cbValue < 0 )
	{
		if ( pElement->bConstructed )
		{
			INT cbValue = 0;

			if ( pElement->cSubElements < 0 || ( pElement->cSubElements > 0 && !pElement->pSubElements ) )
				return -1;
			for ( INT iElement = 0; iElement < pElement->cSubElements; iElement++ )
			{
				INT cbElement = asnEncodedLength( &pElement->pSubElements[iElement] );

				if ( cbElement < 0 || cbValue > INT_MAX - cbElement )
					return -1;
				cbValue += cbElement;
			}
			pElement->cbValue = cbValue;
		}
		else
		{
			pElement->cbValue = pElement->cbObject;
		}
	}
	return pElement->cbValue;
}

static INT asnWriteValue( ASN_ELEMENT *pElement, BYTE *pbDestination, INT iDestinationOffset )
{
	INT cbWritten = 0;
	INT cbValue;

	if ( !pElement || !pbDestination || iDestinationOffset < 0 )
		return 0;

	if ( pElement->bConstructed )
	{
		if ( pElement->cSubElements < 0 || ( pElement->cSubElements > 0 && !pElement->pSubElements ) )
			return 0;
		for ( INT iElement = 0; iElement < pElement->cSubElements; iElement++ )
		{
			if ( cbWritten > INT_MAX - iDestinationOffset )
				return 0;
			INT cbElement =
				asnWriteElement( &pElement->pSubElements[iElement], pbDestination, iDestinationOffset + cbWritten );

			if ( cbElement <= 0 || cbWritten > INT_MAX - cbElement )
				return 0;
			cbWritten += cbElement;
		}
	}
	else
	{
		cbValue = asnValueLength( pElement );
		if ( cbValue < 0 )
			return 0;
		if ( cbValue > 0 )
		{
			if ( !pElement->pbObject || pElement->iValueOffset < 0 || pElement->cbObjectCapacity < 0 ||
				 pElement->iValueOffset > pElement->cbObjectCapacity - cbValue )
				return 0;
			memcpy( pbDestination + iDestinationOffset, pElement->pbObject + pElement->iValueOffset,
					( SIZE_T )cbValue );
			cbWritten = cbValue;
		}
	}

	return cbWritten;
}

static INT asnWriteElement( ASN_ELEMENT *pElement, BYTE *pbDestination, INT iDestinationOffset )
{
	INT iOffset = iDestinationOffset;

	if ( !pElement || !pbDestination || iDestinationOffset < 0 )
		return 0;

	if ( pElement->bHasEncodedHeader )
	{
		if ( !pElement->pbObject || pElement->iObjectOffset < 0 || pElement->cbObject < 0 ||
			 pElement->cbObjectCapacity < 0 ||
			 pElement->iObjectOffset > pElement->cbObjectCapacity - pElement->cbObject )
			return 0;
		memcpy( pbDestination + iOffset, pElement->pbObject + pElement->iObjectOffset, ( SIZE_T )pElement->cbObject );
		return pElement->cbObject;
	}

	INT iFirstByte = ( pElement->iTagClass << 6 ) + ( pElement->bConstructed ? 0x20 : 0x00 );
	if ( pElement->iTagValue < 0x1F )
	{
		iFirstByte |= ( pElement->iTagValue & 0x1F );
		pbDestination[iOffset++] = ( BYTE )iFirstByte;
	}
	else
	{
		iFirstByte |= 0x1F;
		pbDestination[iOffset++] = ( BYTE )iFirstByte;

		INT cShift = 0;
		for ( INT iValue = pElement->iTagValue; iValue > 0; iValue >>= 7, cShift += 7 )
			;
		while ( cShift > 0 )
		{
			INT iTagByte;

			cShift -= 7;
			iTagByte = ( pElement->iTagValue >> cShift ) & 0x7F;
			if ( cShift != 0 )
				iTagByte |= 0x80;
			pbDestination[iOffset++] = ( BYTE )iTagByte;
		}
	}

	INT cbValue = asnValueLength( pElement );
	if ( cbValue < 0 )
		return 0;
	if ( cbValue < 0x80 )
	{
		pbDestination[iOffset++] = ( BYTE )cbValue;
	}
	else
	{
		INT cShift = 0;
		for ( INT iValue = cbValue; iValue > 0; iValue >>= 8, cShift += 8 )
			;
		pbDestination[iOffset++] = ( BYTE )( 0x80 + ( cShift >> 3 ) );
		while ( cShift > 0 )
		{
			cShift -= 8;
			pbDestination[iOffset++] = ( BYTE )( cbValue >> cShift );
		}
	}

	INT cbWritten = asnWriteValue( pElement, pbDestination, iOffset );
	if ( cbWritten != cbValue )
		return 0;
	iOffset += cbWritten;

	return iOffset - iDestinationOffset;
}

BOOL asnEncode( ASN_ELEMENT *pElement, BYTE **ppbData, INT *pcbData )
{
	INT cbEncoded;
	INT cbWritten;

	if ( !pElement || !ppbData || !pcbData )
		return TRUE;

	*ppbData  = NULL;
	*pcbData  = 0;
	cbEncoded = asnEncodedLength( pElement );
	if ( cbEncoded <= 0 )
		return TRUE;

	*ppbData = memAlloc( ( SIZE_T )cbEncoded );
	if ( !*ppbData )
	{
		return TRUE;
	}

	cbWritten = asnWriteElement( pElement, *ppbData, 0 );
	if ( cbWritten != cbEncoded )
	{
		SecureZeroMemory( *ppbData, ( SIZE_T )cbEncoded );
		VirtualFree( *ppbData, 0, MEM_RELEASE );
		*ppbData = NULL;
		return TRUE;
	}

	*pcbData = cbWritten;
	return FALSE;
}

static BOOL asnReadHeader( BYTE *pbBuffer, INT iOffset, INT cbMaximum, PASN_HEADER pHeader );

static INT parseDecimalPair( PCSTR pszValue, INT iOffset, PBOOL pbValid )
{
	CHAR chFirst;
	CHAR chSecond;

	if ( !pbValid )
		return -1;
	if ( !pszValue || iOffset < 0 || ( SIZE_T )( iOffset + 1 ) >= strlen( pszValue ) )
	{
		*pbValid = FALSE;
		return -1;
	}
	chFirst	 = pszValue[iOffset];
	chSecond = pszValue[iOffset + 1];
	if ( chFirst < '0' || chFirst > '9' || chSecond < '0' || chSecond > '9' )
	{
		*pbValid = FALSE;
		return -1;
	}
	return 10 * ( chFirst - '0' ) + ( chSecond - '0' );
}

BOOL asnHasTag( ASN_ELEMENT *pElement, INT iTagClass, INT iTagValue )
{
	return pElement && pElement->iTagClass == iTagClass && pElement->iTagValue == iTagValue;
}

static BOOL asnReadValueByte( ASN_ELEMENT *pElement, INT iOffset, INT *pOutput )
{
	if ( !pElement || !pOutput || pElement->bConstructed || !pElement->pbObject || iOffset < 0 ||
		 pElement->iValueOffset < 0 || pElement->cbValue < 0 || pElement->cbObjectCapacity < 0 ||
		 iOffset >= pElement->cbValue || pElement->iValueOffset > pElement->cbObjectCapacity - pElement->cbValue )
		return TRUE;
	*pOutput = pElement->pbObject[pElement->iValueOffset + iOffset];
	return FALSE;
}

static BOOL asnDecodeElement( BYTE *pbBuffer, INT cbBuffer, INT iOffset, INT cbData, UINT uiDepth,
							  ASN_ELEMENT *pElement )
{
	ASN_HEADER stHeader = { 0 };

	if ( !pElement || !pbBuffer || cbBuffer <= 0 || iOffset < 0 || cbData <= 0 || iOffset > cbBuffer - cbData ||
		 uiDepth >= ASN_MAX_NESTING_DEPTH || asnReadHeader( pbBuffer, iOffset, cbData, &stHeader ) )
		return TRUE;
	ZeroMemory( pElement, sizeof( *pElement ) );

	pElement->iTagClass			= stHeader.iTagClass;
	pElement->iTagValue			= stHeader.iTagValue;
	pElement->bConstructed		= stHeader.bConstructed;
	pElement->pbObject			= pbBuffer;
	pElement->cbObjectCapacity	= cbBuffer;
	pElement->iObjectOffset		= iOffset;
	pElement->cbObject			= stHeader.cbObject;
	pElement->iValueOffset		= stHeader.iValueOffset;
	pElement->cbValue			= stHeader.cbValue;
	pElement->bHasEncodedHeader = TRUE;

	if ( stHeader.bConstructed )
	{
		iOffset			 = stHeader.iValueOffset;
		INT iLimit		 = stHeader.iValueOffset + stHeader.cbValue;
		INT cSubElements = 0;

		while ( iOffset < iLimit )
		{
			ASN_HEADER stChildHeader = { 0 };

			if ( asnReadHeader( pbBuffer, iOffset, iLimit - iOffset, &stChildHeader ) ||
				 cSubElements == ASN_MAX_SUBELEMENTS )
				return TRUE;
			iOffset += stChildHeader.cbObject;
			cSubElements++;
		}

		if ( cSubElements == 0 )
		{
			pElement->pSubElements = NULL;
			pElement->cSubElements = 0;
			return FALSE;
		}

		iOffset			= stHeader.iValueOffset;
		INT iSubElement = 0;

		pElement->pSubElements = memAlloc( sizeof( ASN_ELEMENT ) * ( SIZE_T )cSubElements );
		if ( !pElement->pSubElements )
			return TRUE;
		pElement->cSubElements = cSubElements;

		while ( iOffset < iLimit && iSubElement < cSubElements )
		{
			if ( asnDecodeElement( pbBuffer, cbBuffer, iOffset, iLimit - iOffset, uiDepth + 1,
								   &pElement->pSubElements[iSubElement] ) )
			{
				asnRelease( pElement );
				return TRUE;
			}
			iOffset += pElement->pSubElements[iSubElement].cbObject;
			iSubElement++;
		}
	}
	else
	{
		pElement->pSubElements = NULL;
		pElement->cSubElements = 0;
	}
	return FALSE;
}

static BOOL asnReadHeader( BYTE *pbBuffer, INT iOffset, INT cbMaximum, PASN_HEADER pHeader )
{
	INT iLengthByte;
	INT iLimit;
	INT iOriginalOffset = iOffset;

	if ( !pbBuffer || !pHeader || iOffset < 0 || cbMaximum <= 0 || iOffset > INT_MAX - cbMaximum )
		return TRUE;

	iLimit = iOffset + cbMaximum;
	if ( iOffset >= iLimit )
		return TRUE;
	pHeader->iTagValue	  = pbBuffer[iOffset++];
	pHeader->bConstructed = ( pHeader->iTagValue & 0x20 ) != 0;
	pHeader->iTagClass	  = pHeader->iTagValue >> 6;
	pHeader->iTagValue &= 0x1F;
	if ( pHeader->iTagValue == 0x1F )
	{
		BOOL bFirstTagByte = TRUE;

		pHeader->iTagValue = 0;
		for ( ;; )
		{
			INT iTagByte;
			INT iTagPart;

			if ( iOffset >= iLimit )
				return TRUE;
			iTagByte = pbBuffer[iOffset++];
			iTagPart = iTagByte & 0x7F;
			if ( ( bFirstTagByte && iTagPart == 0 ) || pHeader->iTagValue > ( INT_MAX - iTagPart ) / 128 )
				return TRUE;
			pHeader->iTagValue = pHeader->iTagValue * 128 + iTagPart;
			bFirstTagByte	   = FALSE;
			if ( ( iTagByte & 0x80 ) == 0 )
				break;
		}
		if ( pHeader->iTagValue < 0x1F )
			return TRUE;
	}
	if ( pHeader->iTagClass == ASN_UNIVERSAL && pHeader->iTagValue == 0 )
		return TRUE;

	if ( iOffset >= iLimit )
		return TRUE;
	iLengthByte = pbBuffer[iOffset++];
	if ( iLengthByte == 0x80 )
		return TRUE;
	if ( iLengthByte > 0x80 )
	{
		INT cbLengthOctets = iLengthByte & 0x7F;

		if ( cbLengthOctets <= 0 || cbLengthOctets > ( INT )sizeof( INT ) || cbLengthOctets > iLimit - iOffset ||
			 pbBuffer[iOffset] == 0 )
			return TRUE;
		pHeader->cbValue = 0;
		while ( cbLengthOctets-- > 0 )
		{
			INT iLengthPart = pbBuffer[iOffset++];

			if ( pHeader->cbValue > ( INT_MAX - iLengthPart ) / 256 )
				return TRUE;
			pHeader->cbValue = pHeader->cbValue * 256 + iLengthPart;
		}
		if ( pHeader->cbValue < 0x80 )
			return TRUE;
	}
	else
	{
		pHeader->cbValue = iLengthByte;
	}

	pHeader->iValueOffset = iOffset;
	if ( pHeader->cbValue > iLimit - iOffset )
		return TRUE;
	iOffset += pHeader->cbValue;
	pHeader->cbObject = iOffset - iOriginalOffset;
	return FALSE;
}

BOOL asnDecode( BYTE *pbData, INT cbData, ASN_ELEMENT *pElement )
{
	ASN_HEADER stHeader = { 0 };
	BYTE	  *pbObject = NULL;

	if ( !pbData || cbData <= 0 || !pElement )
		return TRUE;

	ZeroMemory( pElement, sizeof( *pElement ) );
	if ( asnReadHeader( pbData, 0, cbData, &stHeader ) )
		return TRUE;

	if ( stHeader.cbObject != cbData )
		return TRUE;
	pbObject = memClone( pbData, ( SIZE_T )stHeader.cbObject );
	if ( !pbObject )
		return TRUE;
	if ( asnDecodeElement( pbObject, stHeader.cbObject, 0, stHeader.cbObject, 0, pElement ) )
	{
		asnRelease( pElement );
		SecureZeroMemory( pbObject, ( SIZE_T )stHeader.cbObject );
		VirtualFree( pbObject, 0, MEM_RELEASE );
		return TRUE;
	}
	pElement->bOwnsObject = TRUE;

	return FALSE;
}

BOOL asnGetInteger( ASN_ELEMENT *pElement, LONG *pOutput )
{
	ULONG ulValue = 0;
	INT	  iFirstByte;
	INT	  cbValue;

	if ( !pElement || !pOutput || pElement->bConstructed || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_INTEGER ) )
		return TRUE;
	cbValue = asnValueLength( pElement );
	if ( cbValue <= 0 || cbValue > ( INT )sizeof( LONG ) || asnReadValueByte( pElement, 0, &iFirstByte ) )
		return TRUE;
	if ( cbValue > 1 )
	{
		INT iSecondByte;

		if ( asnReadValueByte( pElement, 1, &iSecondByte ) || ( iFirstByte == 0x00 && ( iSecondByte & 0x80 ) == 0 ) ||
			 ( iFirstByte == 0xFF && ( iSecondByte & 0x80 ) != 0 ) )
			return TRUE;
	}
	for ( INT iByte = 0; iByte < cbValue; iByte++ )
	{
		INT iValueByte;

		if ( asnReadValueByte( pElement, iByte, &iValueByte ) )
			return TRUE;
		ulValue = ( ulValue << 8 ) | ( ULONG )iValueByte;
	}
	if ( ( iFirstByte & 0x80 ) != 0 && cbValue < ( INT )sizeof( LONG ) )
		ulValue |= ULONG_MAX << ( cbValue * 8 );
	*pOutput = ( LONG )ulValue;
	return FALSE;
}

static BOOL asnGetUnsignedInteger( ASN_ELEMENT *pElement, PUINT puiOutput )
{
	ULONG ulValue = 0;
	INT	  cbValue;
	INT	  iOffset = 0;
	INT	  iFirstByte;

	if ( !pElement || !puiOutput || pElement->bConstructed || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_INTEGER ) )
		return TRUE;
	cbValue = asnValueLength( pElement );
	if ( cbValue <= 0 || cbValue > ( INT )sizeof( UINT ) + 1 || asnReadValueByte( pElement, 0, &iFirstByte ) )
		return TRUE;
	if ( cbValue == ( INT )sizeof( UINT ) + 1 )
	{
		INT iSecondByte;

		if ( iFirstByte != 0 || asnReadValueByte( pElement, 1, &iSecondByte ) || ( iSecondByte & 0x80 ) == 0 )
			return TRUE;
		iOffset = 1;
		cbValue--;
		iFirstByte = iSecondByte;
	}
	if ( iOffset == 0 && ( iFirstByte & 0x80 ) != 0 )
		return TRUE;
	if ( iOffset == 0 && cbValue > 1 && iFirstByte == 0 )
	{
		INT iSecondByte;

		if ( asnReadValueByte( pElement, 1, &iSecondByte ) || ( iSecondByte & 0x80 ) == 0 )
			return TRUE;
	}
	for ( INT iByte = 0; iByte < cbValue; iByte++ )
	{
		INT iValueByte;

		if ( asnReadValueByte( pElement, iOffset + iByte, &iValueByte ) )
			return TRUE;
		ulValue = ( ulValue << 8 ) | ( ULONG )iValueByte;
	}
	*puiOutput = ( UINT )ulValue;
	return FALSE;
}

BOOL asnGetOctetString( ASN_ELEMENT *pElement, BYTE **pOutput, INT *cbData )
{
	if ( !pElement || !pOutput || !cbData || pElement->bConstructed ||
		 !asnHasTag( pElement, ASN_UNIVERSAL, ASN_OCTET_STRING ) )
		return TRUE;
	*pOutput = NULL;
	*cbData	 = 0;
	*cbData	 = asnValueLength( pElement );
	if ( *cbData < 0 )
		return TRUE;
	if ( *cbData == 0 )
		return FALSE;

	*pOutput = memAlloc( ( SIZE_T )*cbData );
	if ( !*pOutput )
	{
		return TRUE;
	}

	if ( asnWriteValue( pElement, *pOutput, 0 ) != *cbData )
	{
		SecureZeroMemory( *pOutput, ( SIZE_T )*cbData );
		VirtualFree( *pOutput, 0, MEM_RELEASE );
		*pOutput = NULL;
		*cbData	 = 0;
		return TRUE;
	}

	return FALSE;
}

BOOL asnGetString( ASN_ELEMENT *pElement, PCHAR *pOutput )
{
	INT cbString;

	if ( !pElement || !pOutput || pElement->bConstructed || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_GENERAL_STRING ) )
		return TRUE;
	*pOutput = NULL;
	cbString = asnValueLength( pElement );
	if ( cbString <= 0 || !pElement->pbObject || pElement->iValueOffset < 0 || pElement->cbObjectCapacity < 0 ||
		 pElement->iValueOffset > pElement->cbObjectCapacity - cbString )
		return TRUE;
	if ( memchr( pElement->pbObject + pElement->iValueOffset, 0, ( SIZE_T )cbString ) )
		return TRUE;
	*pOutput = memAlloc( ( SIZE_T )cbString + 1 );
	if ( !*pOutput )
		return TRUE;
	memcpy( *pOutput, pElement->pbObject + pElement->iValueOffset, ( SIZE_T )cbString );
	( *pOutput )[cbString] = 0;
	return FALSE;
}

BOOL asnGetPrincipalName( ASN_ELEMENT *pElement, PRINCIPAL_NAME *pName )
{
	ASN_ELEMENT *pTypeField	 = NULL;
	ASN_ELEMENT *pNamesField = NULL;
	ASN_ELEMENT *pNames;

	if ( !pElement || !pName || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pName, sizeof( *pName ) );
	for ( INT iField = 0; iField < pElement->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pElement->pSubElements[iField];

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 )
			return TRUE;
		if ( pField->iTagValue == 0 )
		{
			if ( pTypeField )
				return TRUE;
			pTypeField = pField;
		}
		else if ( pField->iTagValue == 1 )
		{
			if ( pNamesField )
				return TRUE;
			pNamesField = pField;
		}
		else
		{
			return TRUE;
		}
	}
	if ( !pTypeField || !pNamesField || asnGetInteger( &pTypeField->pSubElements[0], &pName->lNameType ) ||
		 !asnHasTag( &pNamesField->pSubElements[0], ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	pNames = &pNamesField->pSubElements[0];
	if ( pNames->cSubElements <= 0 || ( SIZE_T )pNames->cSubElements > SIZE_MAX / sizeof( PCHAR ) )
		return TRUE;
	pName->cNames	 = pNames->cSubElements;
	pName->ppszNames = memAlloc( sizeof( PCHAR ) * ( SIZE_T )pName->cNames );
	if ( !pName->ppszNames )
		return TRUE;
	for ( INT iName = 0; iName < pName->cNames; iName++ )
	{
		if ( asnGetString( &pNames->pSubElements[iName], &pName->ppszNames[iName] ) )
		{
			releasePrincipalName( pName );
			return TRUE;
		}
	}
	return FALSE;
}

BOOL asnGetEncryptedData( ASN_ELEMENT *pElement, ENCRYPTED_DATA *pData )
{
	LONG lValue;
	BOOL bHasEtype	= FALSE;
	BOOL bHasKvno	= FALSE;
	BOOL bHasCipher = FALSE;
	BOOL bFailure	= TRUE;

	if ( !pElement || !pData || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pData, sizeof( *pData ) );
	for ( INT iField = 0; iField < pElement->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pElement->pSubElements[iField];

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 )
			goto Cleanup;
		switch ( pField->iTagValue )
		{
		case 0:
			if ( bHasEtype || asnGetInteger( &pField->pSubElements[0], &lValue ) )
				goto Cleanup;
			pData->iEtype = ( INT )lValue;
			bHasEtype	  = TRUE;
			break;
		case 1:
			if ( bHasKvno || asnGetUnsignedInteger( &pField->pSubElements[0], &pData->uiKvno ) )
				goto Cleanup;
			bHasKvno = TRUE;
			break;
		case 2:
			if ( bHasCipher || asnGetOctetString( &pField->pSubElements[0], &pData->pbCipher, &pData->cbCipher ) ||
				 pData->cbCipher <= 0 )
				goto Cleanup;
			bHasCipher = TRUE;
			break;
		default:
			goto Cleanup;
		}
	}
	bFailure = !bHasEtype || !bHasCipher;

Cleanup:
	if ( bFailure )
		releaseEncryptedData( pData );
	return bFailure;
}

BOOL asnGetTicket( ASN_ELEMENT *pElement, KERBEROS_TICKET *pTicket )
{
	LONG lValue;
	UINT uiFields = 0;
	BOOL bFailure = TRUE;

	if ( !pElement || !pTicket || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pTicket, sizeof( *pTicket ) );
	for ( INT iField = 0; iField < pElement->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pElement->pSubElements[iField];

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 || pField->iTagValue < 0 ||
			 pField->iTagValue > 3 || ( uiFields & ( 1U << pField->iTagValue ) ) != 0 )
			goto Cleanup;
		switch ( pField->iTagValue )
		{
		case 0:
			if ( asnGetInteger( &pField->pSubElements[0], &lValue ) )
				goto Cleanup;
			pTicket->iTicketVersion = ( INT )lValue;
			break;
		case 1:
			if ( asnGetString( &pField->pSubElements[0], &pTicket->pszRealm ) )
				goto Cleanup;
			break;
		case 2:
			if ( asnGetPrincipalName( &pField->pSubElements[0], &pTicket->stServiceName ) )
				goto Cleanup;
			break;
		case 3:
			if ( asnGetEncryptedData( &pField->pSubElements[0], &pTicket->stEncryptedPart ) )
				goto Cleanup;
			break;
		}
		uiFields |= 1U << pField->iTagValue;
	}
	if ( uiFields == 0x0F && pTicket->iTicketVersion == KRB_PROTOCOL_VERSION )
		bFailure = FALSE;

Cleanup:
	if ( bFailure )
	{
		if ( pTicket->pszRealm )
			VirtualFree( pTicket->pszRealm, 0, MEM_RELEASE );
		releasePrincipalName( &pTicket->stServiceName );
		releaseEncryptedData( &pTicket->stEncryptedPart );
		ZeroMemory( pTicket, sizeof( *pTicket ) );
	}
	return bFailure;
}

static BOOL asnGetEncryptionKey( ASN_ELEMENT *pElement, ENCRYPTION_KEY *pEncryptionKey )
{
	ASN_ELEMENT *pSequence;
	LONG		 lValue;
	BOOL		 bHasType  = FALSE;
	BOOL		 bHasValue = FALSE;
	BOOL		 bFailure  = TRUE;

	if ( !pElement || !pEncryptionKey || pElement->cSubElements != 1 ||
		 !asnHasTag( &pElement->pSubElements[0], ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pEncryptionKey, sizeof( *pEncryptionKey ) );
	pSequence = &pElement->pSubElements[0];
	for ( INT iField = 0; iField < pSequence->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField = &pSequence->pSubElements[iField];

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 )
			goto Cleanup;
		switch ( pField->iTagValue )
		{
		case 0:
			if ( bHasType || asnGetInteger( &pField->pSubElements[0], &lValue ) )
				goto Cleanup;
			pEncryptionKey->iKeyType = ( INT )lValue;
			bHasType				 = TRUE;
			break;
		case 1:
			if ( bHasValue ||
				 asnGetOctetString( &pField->pSubElements[0], &pEncryptionKey->pbKey, &pEncryptionKey->cbKey ) ||
				 pEncryptionKey->cbKey <= 0 )
				goto Cleanup;
			bHasValue = TRUE;
			break;
		default:
			goto Cleanup;
		}
	}
	bFailure = !bHasType || !bHasValue;

Cleanup:
	if ( bFailure )
		releaseEncryptionKey( pEncryptionKey );
	return bFailure;
}

static BOOL asnGetBitStringUint32( ASN_ELEMENT *pElement, PUINT puiValue )
{
	INT	 iByte;
	UINT uiValue = 0;

	if ( !pElement || !puiValue || pElement->bConstructed || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_BIT_STRING ) ||
		 asnValueLength( pElement ) != 5 || asnReadValueByte( pElement, 0, &iByte ) || iByte != 0 )
		return TRUE;
	for ( INT iOffset = 1; iOffset < 5; iOffset++ )
	{
		if ( asnReadValueByte( pElement, iOffset, &iByte ) )
			return TRUE;
		uiValue = ( uiValue << 8 ) | ( UINT )iByte;
	}
	*puiValue = uiValue;
	return FALSE;
}

static BOOL asnGetTime( ASN_ELEMENT *pElement, PKERBEROS_TIME pTime )
{
	CHAR	   szTime[16] = { 0 };
	INT		   cchTime;
	BOOL	   bGood  = TRUE;
	SYSTEMTIME stTime = { 0 };
	FILETIME   stFileTime;

	if ( !pElement || !pTime || pElement->bConstructed || pElement->iTagClass != ASN_UNIVERSAL ||
		 pElement->iTagValue != ASN_GENERALIZED_TIME )
		return TRUE;
	ZeroMemory( pTime, sizeof( *pTime ) );
	cchTime = asnValueLength( pElement );
	if ( cchTime != 15 )
		return TRUE;

	if ( asnWriteValue( pElement, ( PBYTE )szTime, 0 ) != cchTime )
		return TRUE;
	if ( szTime[14] != 'Z' )
		return TRUE;
	for ( INT iDigit = 0; iDigit < 14; iDigit++ )
	{
		if ( szTime[iDigit] < '0' || szTime[iDigit] > '9' )
			return TRUE;
	}

	pTime->iYear   = parseDecimalPair( szTime, 0, &bGood ) * 100 + parseDecimalPair( szTime, 2, &bGood );
	pTime->iMonth  = parseDecimalPair( szTime, 4, &bGood );
	pTime->iDay	   = parseDecimalPair( szTime, 6, &bGood );
	pTime->iHour   = parseDecimalPair( szTime, 8, &bGood );
	pTime->iMinute = parseDecimalPair( szTime, 10, &bGood );
	pTime->iSecond = parseDecimalPair( szTime, 12, &bGood );
	if ( !bGood )
		return TRUE;
	stTime.wYear   = ( WORD )pTime->iYear;
	stTime.wMonth  = ( WORD )pTime->iMonth;
	stTime.wDay	   = ( WORD )pTime->iDay;
	stTime.wHour   = ( WORD )pTime->iHour;
	stTime.wMinute = ( WORD )pTime->iMinute;
	stTime.wSecond = ( WORD )pTime->iSecond;
	if ( !SystemTimeToFileTime( &stTime, &stFileTime ) )
	{
		ZeroMemory( pTime, sizeof( *pTime ) );
		return TRUE;
	}
	pTime->bIsSet = TRUE;
	return FALSE;
}

BOOL asnGetEncKDCRepPart( ASN_ELEMENT *pElement, ENC_KDC_REP_PART *pReplyPart )
{
	KERBEROS_TIME stIgnoredTime = { 0 };
	UINT		  uiFields		= 0;
	BOOL		  bFailure		= TRUE;

	if ( !pElement || !pReplyPart || !asnHasTag( pElement, ASN_UNIVERSAL, ASN_SEQUENCE ) )
		return TRUE;
	ZeroMemory( pReplyPart, sizeof( *pReplyPart ) );
	for ( INT iField = 0; iField < pElement->cSubElements; iField++ )
	{
		ASN_ELEMENT *pField	   = &pElement->pSubElements[iField];
		INT			 iTagValue = pField->iTagValue;

		if ( pField->iTagClass != ASN_CONTEXT || pField->cSubElements != 1 || iTagValue < 0 || iTagValue > 11 )
			goto Cleanup;
		if ( ( uiFields & ( 1U << iTagValue ) ) != 0 )
			goto Cleanup;
		uiFields |= 1U << iTagValue;
		switch ( iTagValue )
		{
		case 0:
			if ( asnGetEncryptionKey( pField, &pReplyPart->stKey ) )
				goto Cleanup;
			break;
		case 1:
			if ( !asnHasTag( &pField->pSubElements[0], ASN_UNIVERSAL, ASN_SEQUENCE ) )
				goto Cleanup;
			break;
		case 2:
			if ( asnGetUnsignedInteger( &pField->pSubElements[0], &pReplyPart->uiNonce ) )
				goto Cleanup;
			break;
		case 3:
			if ( asnGetTime( &pField->pSubElements[0], &stIgnoredTime ) )
				goto Cleanup;
			break;
		case 4:
			if ( asnGetBitStringUint32( &pField->pSubElements[0], &pReplyPart->uiFlags ) )
				goto Cleanup;
			break;
		case 5:
			if ( asnGetTime( &pField->pSubElements[0], &pReplyPart->stAuthTime ) )
				goto Cleanup;
			break;
		case 6:
			if ( asnGetTime( &pField->pSubElements[0], &pReplyPart->stStartTime ) )
				goto Cleanup;
			break;
		case 7:
			if ( asnGetTime( &pField->pSubElements[0], &pReplyPart->stEndTime ) )
				goto Cleanup;
			break;
		case 8:
			if ( asnGetTime( &pField->pSubElements[0], &pReplyPart->stRenewUntil ) )
				goto Cleanup;
			break;
		case 9:
			if ( asnGetString( &pField->pSubElements[0], &pReplyPart->pszRealm ) )
				goto Cleanup;
			break;
		case 10:
			if ( asnGetPrincipalName( &pField->pSubElements[0], &pReplyPart->stServiceName ) )
				goto Cleanup;
			break;
		case 11:
			if ( !asnHasTag( &pField->pSubElements[0], ASN_UNIVERSAL, ASN_SEQUENCE ) )
				goto Cleanup;
			break;
		default:
			goto Cleanup;
		}
	}
	if ( ( uiFields & ( ( 1U << 0 ) | ( 1U << 1 ) | ( 1U << 2 ) | ( 1U << 4 ) | ( 1U << 5 ) | ( 1U << 7 ) |
						( 1U << 9 ) | ( 1U << 10 ) ) ) == ( ( 1U << 0 ) | ( 1U << 1 ) | ( 1U << 2 ) | ( 1U << 4 ) |
															( 1U << 5 ) | ( 1U << 7 ) | ( 1U << 9 ) | ( 1U << 10 ) ) )
		bFailure = FALSE;

Cleanup:
	if ( bFailure )
	{
		releaseEncryptionKey( &pReplyPart->stKey );
		if ( pReplyPart->pszRealm )
			VirtualFree( pReplyPart->pszRealm, 0, MEM_RELEASE );
		releasePrincipalName( &pReplyPart->stServiceName );
		ZeroMemory( pReplyPart, sizeof( *pReplyPart ) );
	}
	return bFailure;
}
