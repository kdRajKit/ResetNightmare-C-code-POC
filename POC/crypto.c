/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        crypto.c                                                                                             *
*   DESCRIPCION:   Primitivas criptograficas Kerberos y conversion de claves.                                          *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                           IMPLEMENTACION CRIPTOGRAFICA                                               *
***********************************************************************************************************************/

VOID releaseEncryptionKey( ENCRYPTION_KEY *pKey )
{
	if ( !pKey )
		return;
	if ( pKey->pbKey )
	{
		if ( pKey->cbKey > 0 )
			SecureZeroMemory( pKey->pbKey, ( SIZE_T )pKey->cbKey );
		VirtualFree( pKey->pbKey, 0, MEM_RELEASE );
	}
	ZeroMemory( pKey, sizeof( *pKey ) );
}

VOID releaseEncryptedData( ENCRYPTED_DATA *pData )
{
	if ( !pData )
		return;
	if ( pData->pbCipher )
	{
		if ( pData->cbCipher > 0 )
			SecureZeroMemory( pData->pbCipher, ( SIZE_T )pData->cbCipher );
		VirtualFree( pData->pbCipher, 0, MEM_RELEASE );
	}
	ZeroMemory( pData, sizeof( *pData ) );
}

static BOOL transformKerberosBuffer( BOOL bEncrypt, const BYTE *pbInput, INT cbInput, const ENCRYPTION_KEY *pKey,
									 INT iKeyUsage, PBYTE *ppbOutput, PINT pcbOutput )
{
	PKERB_ECRYPT		 pCryptoSystem = NULL;
	PKERB_ECRYPT_ENCRYPT pfnTransform;
	PVOID				 pContext = NULL;
	ULONG				 cbResult;
	ULONG				 cbCapacity;
	ULONG				 ulRemainder;
	NTSTATUS			 ntStatus;
	BOOL				 bFailure = TRUE;

	if ( !ppbOutput || !pcbOutput )
		return TRUE;
	*ppbOutput = NULL;
	*pcbOutput = 0;
	if ( !pbInput || cbInput <= 0 || !pKey || !pKey->pbKey || pKey->cbKey <= 0 || pKey->iKeyType < 0 || iKeyUsage < 0 )
		return TRUE;

	if ( !NT_SUCCESS( CDLocateCSystem( ( ULONG )pKey->iKeyType, &pCryptoSystem ) ) || !pCryptoSystem ||
		 pCryptoSystem->cbKey != ( ULONG )pKey->cbKey || !pCryptoSystem->pfnInitialize || !pCryptoSystem->pfnFinish )
		return TRUE;
	pfnTransform = bEncrypt ? pCryptoSystem->pfnEncrypt : pCryptoSystem->pfnDecrypt;
	if ( !pfnTransform || ( bEncrypt && pCryptoSystem->cbBlock == 0 ) )
		return TRUE;
	if ( !NT_SUCCESS(
			 pCryptoSystem->pfnInitialize( pKey->pbKey, pCryptoSystem->cbKey, ( ULONG )iKeyUsage, &pContext ) ) )
		return TRUE;

	cbCapacity = ( ULONG )cbInput;
	if ( bEncrypt )
	{
		ulRemainder = cbCapacity % pCryptoSystem->cbBlock;
		if ( ulRemainder )
		{
			ULONG cbPadding = pCryptoSystem->cbBlock - ulRemainder;

			if ( cbCapacity > ULONG_MAX - cbPadding )
				goto Cleanup;
			cbCapacity += cbPadding;
		}
		if ( cbCapacity > ULONG_MAX - pCryptoSystem->cbHeader )
			goto Cleanup;
		cbCapacity += pCryptoSystem->cbHeader;
	}
	if ( cbCapacity == 0 || cbCapacity > INT_MAX )
		goto Cleanup;

	*ppbOutput = memAlloc( cbCapacity );
	if ( !*ppbOutput )
		goto Cleanup;
	cbResult = cbCapacity;
	ntStatus = pfnTransform( pContext, pbInput, ( ULONG )cbInput, *ppbOutput, &cbResult );
	if ( !NT_SUCCESS( ntStatus ) || cbResult > cbCapacity || cbResult > INT_MAX )
		goto Cleanup;

	*pcbOutput = ( INT )cbResult;
	bFailure   = FALSE;

Cleanup:
	if ( !NT_SUCCESS( pCryptoSystem->pfnFinish( &pContext ) ) && !bFailure )
		bFailure = TRUE;
	if ( bFailure && *ppbOutput )
	{
		SecureZeroMemory( *ppbOutput, cbCapacity );
		VirtualFree( *ppbOutput, 0, MEM_RELEASE );
		*ppbOutput = NULL;
		*pcbOutput = 0;
	}
	return bFailure;
}

BOOL kerberosEncrypt( const BYTE *pbInput, INT cbInput, const ENCRYPTION_KEY *pKey, INT iKeyUsage, PBYTE *ppbOutput,
					  PINT pcbOutput )
{
	return transformKerberosBuffer( TRUE, pbInput, cbInput, pKey, iKeyUsage, ppbOutput, pcbOutput );
}

PCHAR base64Encode( const BYTE *pbInput, SIZE_T cbInput )
{
	static const CHAR szAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	SIZE_T			  cBlocks;
	SIZE_T			  cchOutput;
	PCHAR			  pszOutput;
	SIZE_T			  iInput  = 0;
	SIZE_T			  iOutput = 0;

	if ( ( cbInput > 0 && !pbInput ) || cbInput > SIZE_MAX - 2 )
		return NULL;
	cBlocks = ( cbInput + 2 ) / 3;
	if ( cBlocks > ( SIZE_MAX - 1 ) / 4 )
		return NULL;
	cchOutput = cBlocks * 4;
	pszOutput = memAlloc( cchOutput + 1 );
	if ( !pszOutput )
		return NULL;

	while ( iInput < cbInput )
	{
		UINT uiOctetA = iInput < cbInput ? pbInput[iInput++] : 0;
		UINT uiOctetB = iInput < cbInput ? pbInput[iInput++] : 0;
		UINT uiOctetC = iInput < cbInput ? pbInput[iInput++] : 0;
		UINT uiTriple = ( uiOctetA << 0x10 ) + ( uiOctetB << 0x08 ) + uiOctetC;

		pszOutput[iOutput++] = szAlphabet[( uiTriple >> 18 ) & 0x3F];
		pszOutput[iOutput++] = szAlphabet[( uiTriple >> 12 ) & 0x3F];
		pszOutput[iOutput++] = szAlphabet[( uiTriple >> 6 ) & 0x3F];
		pszOutput[iOutput++] = szAlphabet[uiTriple & 0x3F];
	}

	if ( cbInput % 3 == 1 )
	{
		pszOutput[cchOutput - 1] = '=';
		pszOutput[cchOutput - 2] = '=';
	}
	else if ( cbInput % 3 == 2 )
	{
		pszOutput[cchOutput - 1] = '=';
	}

	pszOutput[cchOutput] = '\0';
	return pszOutput;
}

BOOL kerberosDecrypt( const BYTE *pbInput, INT cbInput, const ENCRYPTION_KEY *pKey, INT iKeyUsage, PBYTE *ppbOutput,
					  PINT pcbOutput )
{
	return transformKerberosBuffer( FALSE, pbInput, cbInput, pKey, iKeyUsage, ppbOutput, pcbOutput );
}

static BOOL utf8ToUnicodeString( PCSTR pszValue, PUNICODE_STRING pValue )
{
	INT cchWide;

	if ( !pszValue || !pValue )
		return FALSE;
	cchWide = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, pszValue, -1, NULL, 0 );
	if ( cchWide <= 0 || cchWide > 32767 )
		return FALSE;

	ZeroMemory( pValue, sizeof( *pValue ) );
	pValue->Buffer = memAlloc( ( SIZE_T )cchWide * sizeof( WCHAR ) );
	if ( !pValue->Buffer ||
		 MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, pszValue, -1, pValue->Buffer, cchWide ) != cchWide )
	{
		if ( pValue->Buffer )
			VirtualFree( pValue->Buffer, 0, MEM_RELEASE );
		ZeroMemory( pValue, sizeof( *pValue ) );
		return FALSE;
	}

	pValue->Length		  = ( USHORT )( ( SIZE_T )( cchWide - 1 ) * sizeof( WCHAR ) );
	pValue->MaximumLength = ( USHORT )( ( SIZE_T )cchWide * sizeof( WCHAR ) );
	return TRUE;
}

BOOL getPasswordKey( PCSTR pszPassword, PCSTR pszSalt, ULONG ulIterations, INT iEtype, ENCRYPTION_KEY *pKey )
{
	PKERB_ECRYPT   pCrypto		  = NULL;
	STRING		   stAnsiPassword = { 0 };
	UNICODE_STRING stPassword	  = { 0 };
	UNICODE_STRING stSalt		  = { 0 };
	NTSTATUS	   ntStatus;
	BOOL		   bFailure = TRUE;

	if ( !pKey )
		goto Cleanup;
	ZeroMemory( pKey, sizeof( *pKey ) );
	if ( !pszPassword || !pszSalt || iEtype < 0 || ulIterations == 0 || ulIterations > KRB_MAX_S2K_ITERATIONS )
		goto Cleanup;

	RtlInitAnsiString( &stAnsiPassword, pszPassword );
	if ( !NT_SUCCESS( CDLocateCSystem( ( ULONG )iEtype, &pCrypto ) ) || !pCrypto || pCrypto->cbKey == 0 ||
		 pCrypto->cbKey > INT_MAX ||
		 !NT_SUCCESS( RtlAnsiStringToUnicodeString( &stPassword, &stAnsiPassword, TRUE ) ) )
		goto Cleanup;
	if ( !pCrypto->pfnHashPasswordNt6 || !utf8ToUnicodeString( pszSalt, &stSalt ) )
		goto Cleanup;

	pKey->iKeyType = iEtype;
	pKey->cbKey	   = ( INT )pCrypto->cbKey;
	pKey->pbKey	   = memAlloc( pCrypto->cbKey );
	if ( !pKey->pbKey )
		goto Cleanup;
	ntStatus = pCrypto->pfnHashPasswordNt6( &stPassword, &stSalt, ulIterations, pKey->pbKey );
	bFailure = !NT_SUCCESS( ntStatus );

Cleanup:
	if ( stSalt.Buffer )
	{
		SecureZeroMemory( stSalt.Buffer, stSalt.MaximumLength );
		VirtualFree( stSalt.Buffer, 0, MEM_RELEASE );
	}
	if ( stPassword.Buffer )
	{
		SecureZeroMemory( stPassword.Buffer, stPassword.MaximumLength );
		RtlFreeUnicodeString( &stPassword );
	}
	if ( bFailure )
		releaseEncryptionKey( pKey );
	return bFailure;
}
