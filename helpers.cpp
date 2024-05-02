

#include "helpers.h"
#include <intsafe.h>

// rcpfdが指すフィールド記述子を、CoTaskMemAllocを使って割り当てたバッファにコピーする。
// そのバッファをppcpfdで返す。

HRESULT FieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
    HRESULT hr;
    *ppcpfd = nullptr;
    DWORD cbStruct = sizeof(**ppcpfd);

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);
    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;
        pcpfd->guidFieldType = rcpfd.guidFieldType;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = nullptr;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);
    }

    return hr;
}

// rcpfdをpcpfdが指すバッファにコピーする。pcpfdの確保は呼び出し側の責任である。
// この関数はCoTaskMemAllocを使用してpcpfd->pszLabelのメモリを確保する。

HRESULT FieldDescriptorCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
)
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;
    cpfd.guidFieldType = rcpfd.guidFieldType;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = nullptr;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}

// この関数は、pwzの長さとポインタpwzをUNICODE_STRING構造体にコピーする。
// この関数は、GetSerialization でクレデンシャルをシリアライズするためだけのものです。
// この関数は文字列ポインタのコピーを作成するだけであることに注意。ストレージを確保することはありません！

HRESULT UnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING* pus
)
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString = wcslen(pwz);
        USHORT usCharCount;
        hr = SizeTToUShort(lenString, &usCharCount);
        if (SUCCEEDED(hr))
        {
            USHORT usSize;
            hr = SizeTToUShort(sizeof(wchar_t), &usSize);
            if (SUCCEEDED(hr))
            {
                hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                if (SUCCEEDED(hr))
                {
                    pus->MaximumLength = pus->Length;
                    pus->Buffer = pwz;
                    hr = S_OK;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// 以下の関数は、Kerb*Pack関数とのみ使用することを意図している。 
// 呼び出し側には正確な要件があり、その制限を尊重するように書かれているためです。

static void _UnicodeStringPackedUnicodeStringCopy(
    __in const UNICODE_STRING& rus,
    __in PWSTR pwzBuffer,
    __out UNICODE_STRING* pus
)
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// KERB_INTERACTIVE_UNLOCK_LOGON のメンバを、渡された文字列への弱い参照で初期化します。 
// これは、後でKerbInteractiveUnlockLogonPackを使用して構造体をシリアライズする場合に便利です。
//
// パスワードは、CPUS_LOGON と CPUS_UNLOCK_WORKSTATION では暗号化された形式で格納される。 
// CPUS_CREDUI では暗号化されません。
// これは、呼び出し元が暗号化された認証情報を受け入れることができるかどうかがわからないためです。


HRESULT KerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    // 注: このメソッドは、KERB_INTERACTIVE_UNLOCK_LOGON を
    // シリアライズされたクレデンシャルでパックするカスタムロジックを使用する。 
    // UnicodeStringInitWithString と KerbInteractiveUnlockLogonPack への
    // 呼び出しを CredPackAuthenticationBuffer への単一の呼び出しで
    // 置き換えることもできますが、この API には欠点があります。
    //
    // もしCPUS_LOGONだけを扱うのであれば、この欠点は問題にならない。 
    // CPUS_UNLOCK_WORKSTATION の場合、CredPackAuthenticationBuffer の
    // 出力バッファを KERB_INTERACTIVE_UNLOCK_LOGON にキャストし、
    // MessageType を KerbWorkstationUnlockLogon に変更できるが、
    // このようなキャストはサポートされない。

    // UNICODE_STRINGS を初期化して、ユーザ名とパスワード文字列を共有する。

    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);
        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
            if (SUCCEEDED(hr))
            {
                // Set a MessageType based on the usage scenario.
                switch (cpus)
                {
                case CPUS_UNLOCK_WORKSTATION:
                    pkil->MessageType = KerbWorkstationUnlockLogon;
                    hr = S_OK;
                    break;

                case CPUS_LOGON:
                    pkil->MessageType = KerbInteractiveLogon;
                    hr = S_OK;
                    break;

                case CPUS_CREDUI:
                    pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0; // MessageType does not apply to CredUI
                    hr = S_OK;
                    break;

                default:
                    hr = E_FAIL;
                    break;
                }

                if (SUCCEEDED(hr))
                {
                    // KERB_INTERACTIVE_UNLOCK_LOGONは単なる一連の構造体である。 
                    // フラット・コピーは出力パラメーターを適切に初期化する。
                    CopyMemory(pkiul, &kiul, sizeof(*pkiul));
                }
            }
        }
    }

    return hr;
}

//
// WinLogonとLSAは "パックされた "KERB_INTERACTIVE_UNLOCK_LOGONを消費する。 
// これらの場合、各 UNICODE_STRING の PWSTR メンバは、実際にはポインタではなく、
// パックされた KERB_INTERACTIVE_UNLOCK_LOGON で表されるバッファ全体のバイトオフセットです。
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> 長さは文字数ではなくバイト数
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainNameは、バッファ内のKERB_...構造体の直後から始まる。
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGSはヌル終端ではありません。
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
//
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT KerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE** prgb,
    _Out_ DWORD* pcb
)
{
    HRESULT hr;

    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));

        //
        // 余分なスペースの先頭にpbBufferをポイントする。
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // KERB_INTERACTIVE_UNLOCK_LOGON内でログオン構造を設定する。
        //
        KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        //
        // 各文字列をコピーし、オフセットされる適切なバッファ・ポインタを修正し、
        // バッファ・ポインタを余分なスペースでコピーされた文字の上に進める
        
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
        pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

//
// この関数は、LsaLookupAuthenticationPackage を含む LSA 関数で使用するために、
// 文字列 pszSourceString を pszDestinationString にパックする

static HRESULT _LsaInitString(
    __out PSTRING pszDestinationString,
    __in PCSTR pszSourceString
)
{
    size_t cchLength = strlen(pszSourceString);
    USHORT usLength;
    HRESULT hr = SizeTToUShort(cchLength, &usLength);
    if (SUCCEEDED(hr))
    {
        pszDestinationString->Buffer = (PCHAR)pszSourceString;
        pszDestinationString->Length = usLength;
        pszDestinationString->MaximumLength = pszDestinationString->Length + 1;
        hr = S_OK;
    }
    return hr;
}

//
// LSA から 'negotiate' AuthPackage を取得する。
// 認証パッケージの詳細については msdn のページを参照のこと：
// https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-msv1_0_lm20_logon
// https://learn.microsoft.com/ja-jp/windows/win32/api/ntsecapi/ns-ntsecapi-msv1_0_lm20_logon

HRESULT RetrieveNegotiateAuthPackage(_Out_ ULONG* pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszKerberosName;
        _LsaInitString(&lsaszKerberosName, NEGOSSP_NAME_A);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

//
// CredProtect API で暗号化した pwzToProtect のコピーを返す。
//
// pwzToProtect は NULL または空文字列であってはならない。
//
static HRESULT _ProtectAndCopyString(
    _In_ PCWSTR pwzToProtect,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtected
)
{
    *ppwzProtected = nullptr;

    // pwzToProtectはconstだが、CredProtectはconstでない文字列を取る。
    // そこで、constでないことが分かっているコピーを作成する。
    PWSTR pwzToProtectCopy;
    HRESULT hr = SHStrDupW(pwzToProtect, &pwzToProtectCopy);
    if (SUCCEEDED(hr))
    {
        // CredProtect の最初の呼び出しで、暗号化された文字列の長さが決定される。
        // NULL 出力バッファを渡しているため、呼び出しは失敗すると予想される。
        //
        // CredProtect の 3 番目のパラメータ、暗号化する pwzToProtectCopy の文字数には NULL 終端を含める必要があることに注意！
        DWORD cchProtected = 0;
        if (!CredProtectW(FALSE, pwzToProtectCopy, (DWORD)wcslen(pwzToProtectCopy) + 1, nullptr, &cchProtected, nullptr))
        {
            DWORD dwErr = GetLastError();

            if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
            {
                // 暗号化された文字列に十分な長さのバッファを確保する。
                PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(wchar_t));
                if (pwzProtected)
                {
                    // CredProtectの2回目の呼び出しで、文字列が実際に暗号化される。
                    if (CredProtectW(FALSE, pwzToProtectCopy, (DWORD)wcslen(pwzToProtectCopy) + 1, pwzProtected, &cchProtected, nullptr))
                    {
                        *ppwzProtected = pwzProtected;
                        hr = S_OK;
                    }
                    else
                    {
                        CoTaskMemFree(pwzProtected);

                        dwErr = GetLastError();
                        hr = HRESULT_FROM_WIN32(dwErr);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }
            else
            {
                hr = HRESULT_FROM_WIN32(dwErr);
            }
        }
        else
        {
            hr = E_UNEXPECTED;
        }

        CoTaskMemFree(pwzToProtectCopy);
    }

    return hr;
}

//
// pwzPassword を暗号化する場合は、CredProtect で暗号化したコピーを返す。
//
// 暗号化されていない場合は、コピーを返す。
//
HRESULT ProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtectedPassword
)
{
    *ppwzProtectedPassword = nullptr;

    HRESULT hr;

    // ProtectAndCopyStringは、空でない文字列のみを対象としています。 
    // 空のパスワードは暗号化する必要はありません。
    if (pwzPassword && *pwzPassword)
    {
        // pwzPasswordはconstだが、CredIsProtectedはconstでない文字列を取る。
        // そこで、constでないことが分かっているコピーを作成する。
        PWSTR pwzPasswordCopy;
        hr = SHStrDupW(pwzPassword, &pwzPasswordCopy);
        if (SUCCEEDED(hr))
        {
            bool bCredAlreadyEncrypted = false;
            CRED_PROTECTION_TYPE protectionType;

            // パスワードがすでに暗号化されている場合は、再度暗号化すべきではない。
            // 暗号化されたパスワードは、例えばターミナル・サービス接続中に 
            // CPUS_LOGON シナリオの SetSerialization で受け取ることができる。
            if (CredIsProtectedW(pwzPasswordCopy, &protectionType))
            {
                if (CredUnprotected != protectionType)
                {
                    bCredAlreadyEncrypted = true;
                }
            }
            // CPUS_CREDUI シナリオでは、パスワードを暗号化すべきではない。 
            // 呼び出し元が暗号化されたパスワードを予期しているか、または扱えるかを知ることはできません。
            if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted)
            {
                hr = SHStrDupW(pwzPasswordCopy, ppwzProtectedPassword);
            }
            else
            {
                hr = _ProtectAndCopyString(pwzPasswordCopy, ppwzProtectedPassword);
            }

            CoTaskMemFree(pwzPasswordCopy);
        }
    }
    else
    {
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}


HRESULT SplitDomainAndUsername(_In_ PCWSTR pszQualifiedUserName, _Outptr_result_nullonfailure_ PWSTR* ppszDomain, _Outptr_result_nullonfailure_ PWSTR* ppszUsername)
{
    HRESULT hr = E_UNEXPECTED;
    *ppszDomain = nullptr;
    *ppszUsername = nullptr;
    PWSTR pszDomain;
    PWSTR pszUsername;
    const wchar_t* pchWhack = wcschr(pszQualifiedUserName, L'\\');
    const wchar_t* pchEnd = pszQualifiedUserName + wcslen(pszQualifiedUserName) - 1;

    if (pchWhack != nullptr)
    {
        const wchar_t* pchDomainBegin = pszQualifiedUserName;
        const wchar_t* pchDomainEnd = pchWhack - 1;
        const wchar_t* pchUsernameBegin = pchWhack + 1;
        const wchar_t* pchUsernameEnd = pchEnd;

        // 実際の文字数。ヌル文字で終端された文字列は含まない。
        size_t lenDomain = pchDomainEnd - pchDomainBegin + 1; 
        pszDomain = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenDomain + 1)));
        if (pszDomain != nullptr)
        {
            hr = StringCchCopyN(pszDomain, lenDomain + 1, pchDomainBegin, lenDomain);
            if (SUCCEEDED(hr))
            {
                // 実際の文字数。ヌル文字で終端された文字列は含まない。
                size_t lenUsername = pchUsernameEnd - pchUsernameBegin + 1;
                pszUsername = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenUsername + 1)));
                if (pszUsername != nullptr)
                {
                    hr = StringCchCopyN(pszUsername, lenUsername + 1, pchUsernameBegin, lenUsername);
                    if (SUCCEEDED(hr))
                    {
                        *ppszDomain = pszDomain;
                        *ppszUsername = pszUsername;
                    }
                    else
                    {
                        CoTaskMemFree(pszUsername);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }

            if (FAILED(hr))
            {
                CoTaskMemFree(pszDomain);
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    return hr;
}