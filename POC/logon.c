/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        logon.c                                                                                              *
*                                                                                                                       *
***********************************************************************************************************************/

#include "resetnightmare.h"

/***********************************************************************************************************************
*                                            IMPLEMENTACION DE LOGON                                                   *
***********************************************************************************************************************/

static BOOL stringToWide( PCSTR pszSource, PWSTR *ppwszDestination )
{
	PWSTR pwszDestination;
	INT	  cchDestination;

	if ( !pszSource || !ppwszDestination )
		return FALSE;
	*ppwszDestination = NULL;
	cchDestination = MultiByteToWideChar( CP_ACP, 0, pszSource, -1, NULL, 0 );
	if ( cchDestination <= 0 )
		return FALSE;
	pwszDestination = memAlloc( ( SIZE_T )cchDestination * sizeof( WCHAR ) );
	if ( !pwszDestination )
		return FALSE;
	if ( MultiByteToWideChar( CP_ACP, 0, pszSource, -1, pwszDestination, cchDestination ) != cchDestination )
	{
		VirtualFree( pwszDestination, 0, MEM_RELEASE );
		return FALSE;
	}
	*ppwszDestination = pwszDestination;
	return TRUE;
}

BOOL execAsPrivUser( PCSTR pszUsername, PCSTR pszDomain, PCSTR pszPassword, PCSTR pszCommand )
{
	STARTUPINFOW			stStartup			= { 0 };
	PROCESS_INFORMATION stProcess			= { 0 };
	PWSTR					pwszUsername		= NULL;
	PWSTR					pwszDomain			= NULL;
	PWSTR					pwszPassword		= NULL;
	PWSTR					pwszCommand			= NULL;
	BOOL					bSuccess			= FALSE;

	if ( !pszUsername || !pszDomain || !pszPassword || !pszCommand )
		return FALSE;
	if ( !stringToWide( pszUsername, &pwszUsername ) || !stringToWide( pszDomain, &pwszDomain ) ||
		 !stringToWide( pszPassword, &pwszPassword ) || !stringToWide( pszCommand, &pwszCommand ) )
		goto Cleanup;
	stStartup.cb = ( DWORD )sizeof( stStartup );
	bSuccess = CreateProcessWithLogonW( pwszUsername, pwszDomain, pwszPassword, LOGON_WITH_PROFILE, NULL, pwszCommand, 0,
									   NULL, NULL, &stStartup, &stProcess );
	if ( bSuccess )
	{
		WaitForSingleObject( stProcess.hProcess, INFINITE );
		CloseHandle( stProcess.hProcess );
		CloseHandle( stProcess.hThread );
	}
	else
	{
		fprintf( stderr, "[-] CreateProcessWithLogonW fallo: %lu.\n", GetLastError() );
	}

Cleanup:
	if ( pwszPassword )
		SecureZeroMemory( pwszPassword, ( ( SIZE_T )lstrlenW( pwszPassword ) + 1U ) * sizeof( WCHAR ) );
	if ( pwszUsername )
		VirtualFree( pwszUsername, 0, MEM_RELEASE );
	if ( pwszDomain )
		VirtualFree( pwszDomain, 0, MEM_RELEASE );
	if ( pwszPassword )
		VirtualFree( pwszPassword, 0, MEM_RELEASE );
	if ( pwszCommand )
		VirtualFree( pwszCommand, 0, MEM_RELEASE );
	return bSuccess;
}
