

#include "helpers.h"
#include <intsafe.h>

// rcpfd���w���t�B�[���h�L�q�q���ACoTaskMemAlloc���g���Ċ��蓖�Ă��o�b�t�@�ɃR�s�[����B
// ���̃o�b�t�@��ppcpfd�ŕԂ��B

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

// rcpfd��pcpfd���w���o�b�t�@�ɃR�s�[����Bpcpfd�̊m�ۂ͌Ăяo�����̐ӔC�ł���B
// ���̊֐���CoTaskMemAlloc���g�p����pcpfd->pszLabel�̃��������m�ۂ���B

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

// ���̊֐��́Apwz�̒����ƃ|�C���^pwz��UNICODE_STRING�\���̂ɃR�s�[����B
// ���̊֐��́AGetSerialization �ŃN���f���V�������V���A���C�Y���邽�߂����̂��̂ł��B
// ���̊֐��͕�����|�C���^�̃R�s�[���쐬���邾���ł��邱�Ƃɒ��ӁB�X�g���[�W���m�ۂ��邱�Ƃ͂���܂���I

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

// �ȉ��̊֐��́AKerb*Pack�֐��Ƃ̂ݎg�p���邱�Ƃ��Ӑ}���Ă���B 
// �Ăяo�����ɂ͐��m�ȗv��������A���̐����𑸏d����悤�ɏ�����Ă��邽�߂ł��B

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
// KERB_INTERACTIVE_UNLOCK_LOGON �̃����o���A�n���ꂽ������ւ̎ア�Q�Ƃŏ��������܂��B 
// ����́A���KerbInteractiveUnlockLogonPack���g�p���č\���̂��V���A���C�Y����ꍇ�ɕ֗��ł��B
//
// �p�X���[�h�́ACPUS_LOGON �� CPUS_UNLOCK_WORKSTATION �ł͈Í������ꂽ�`���Ŋi�[�����B 
// CPUS_CREDUI �ł͈Í�������܂���B
// ����́A�Ăяo�������Í������ꂽ�F�؏����󂯓���邱�Ƃ��ł��邩�ǂ������킩��Ȃ����߂ł��B


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

    // ��: ���̃��\�b�h�́AKERB_INTERACTIVE_UNLOCK_LOGON ��
    // �V���A���C�Y���ꂽ�N���f���V�����Ńp�b�N����J�X�^�����W�b�N���g�p����B 
    // UnicodeStringInitWithString �� KerbInteractiveUnlockLogonPack �ւ�
    // �Ăяo���� CredPackAuthenticationBuffer �ւ̒P��̌Ăяo����
    // �u�������邱�Ƃ��ł��܂����A���� API �ɂ͌��_������܂��B
    //
    // ����CPUS_LOGON�����������̂ł���΁A���̌��_�͖��ɂȂ�Ȃ��B 
    // CPUS_UNLOCK_WORKSTATION �̏ꍇ�ACredPackAuthenticationBuffer ��
    // �o�̓o�b�t�@�� KERB_INTERACTIVE_UNLOCK_LOGON �ɃL���X�g���A
    // MessageType �� KerbWorkstationUnlockLogon �ɕύX�ł��邪�A
    // ���̂悤�ȃL���X�g�̓T�|�[�g����Ȃ��B

    // UNICODE_STRINGS �����������āA���[�U���ƃp�X���[�h����������L����B

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
                    // KERB_INTERACTIVE_UNLOCK_LOGON�͒P�Ȃ��A�̍\���̂ł���B 
                    // �t���b�g�E�R�s�[�͏o�̓p�����[�^�[��K�؂ɏ���������B
                    CopyMemory(pkiul, &kiul, sizeof(*pkiul));
                }
            }
        }
    }

    return hr;
}

//
// WinLogon��LSA�� "�p�b�N���ꂽ "KERB_INTERACTIVE_UNLOCK_LOGON�������B 
// �����̏ꍇ�A�e UNICODE_STRING �� PWSTR �����o�́A���ۂɂ̓|�C���^�ł͂Ȃ��A
// �p�b�N���ꂽ KERB_INTERACTIVE_UNLOCK_LOGON �ŕ\�����o�b�t�@�S�̂̃o�C�g�I�t�Z�b�g�ł��B
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> �����͕������ł͂Ȃ��o�C�g��
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName�́A�o�b�t�@����KERB_...�\���̂̒��ォ��n�܂�B
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS�̓k���I�[�ł͂���܂���B
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
        // �]���ȃX�y�[�X�̐擪��pbBuffer���|�C���g����B
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // KERB_INTERACTIVE_UNLOCK_LOGON���Ń��O�I���\����ݒ肷��B
        //
        KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        //
        // �e��������R�s�[���A�I�t�Z�b�g�����K�؂ȃo�b�t�@�E�|�C���^���C�����A
        // �o�b�t�@�E�|�C���^��]���ȃX�y�[�X�ŃR�s�[���ꂽ�����̏�ɐi�߂�
        
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
// ���̊֐��́ALsaLookupAuthenticationPackage ���܂� LSA �֐��Ŏg�p���邽�߂ɁA
// ������ pszSourceString �� pszDestinationString �Ƀp�b�N����

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
// LSA ���� 'negotiate' AuthPackage ���擾����B
// �F�؃p�b�P�[�W�̏ڍׂɂ��Ă� msdn �̃y�[�W���Q�Ƃ̂��ƁF
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
// CredProtect API �ňÍ������� pwzToProtect �̃R�s�[��Ԃ��B
//
// pwzToProtect �� NULL �܂��͋󕶎���ł����Ă͂Ȃ�Ȃ��B
//
static HRESULT _ProtectAndCopyString(
    _In_ PCWSTR pwzToProtect,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtected
)
{
    *ppwzProtected = nullptr;

    // pwzToProtect��const�����ACredProtect��const�łȂ�����������B
    // �����ŁAconst�łȂ����Ƃ��������Ă���R�s�[���쐬����B
    PWSTR pwzToProtectCopy;
    HRESULT hr = SHStrDupW(pwzToProtect, &pwzToProtectCopy);
    if (SUCCEEDED(hr))
    {
        // CredProtect �̍ŏ��̌Ăяo���ŁA�Í������ꂽ������̒��������肳���B
        // NULL �o�̓o�b�t�@��n���Ă��邽�߁A�Ăяo���͎��s����Ɨ\�z�����B
        //
        // CredProtect �� 3 �Ԗڂ̃p�����[�^�A�Í������� pwzToProtectCopy �̕������ɂ� NULL �I�[���܂߂�K�v�����邱�Ƃɒ��ӁI
        DWORD cchProtected = 0;
        if (!CredProtectW(FALSE, pwzToProtectCopy, (DWORD)wcslen(pwzToProtectCopy) + 1, nullptr, &cchProtected, nullptr))
        {
            DWORD dwErr = GetLastError();

            if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
            {
                // �Í������ꂽ������ɏ\���Ȓ����̃o�b�t�@���m�ۂ���B
                PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(wchar_t));
                if (pwzProtected)
                {
                    // CredProtect��2��ڂ̌Ăяo���ŁA�����񂪎��ۂɈÍ��������B
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
// pwzPassword ���Í�������ꍇ�́ACredProtect �ňÍ��������R�s�[��Ԃ��B
//
// �Í�������Ă��Ȃ��ꍇ�́A�R�s�[��Ԃ��B
//
HRESULT ProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtectedPassword
)
{
    *ppwzProtectedPassword = nullptr;

    HRESULT hr;

    // ProtectAndCopyString�́A��łȂ�������݂̂�ΏۂƂ��Ă��܂��B 
    // ��̃p�X���[�h�͈Í�������K�v�͂���܂���B
    if (pwzPassword && *pwzPassword)
    {
        // pwzPassword��const�����ACredIsProtected��const�łȂ�����������B
        // �����ŁAconst�łȂ����Ƃ��������Ă���R�s�[���쐬����B
        PWSTR pwzPasswordCopy;
        hr = SHStrDupW(pwzPassword, &pwzPasswordCopy);
        if (SUCCEEDED(hr))
        {
            bool bCredAlreadyEncrypted = false;
            CRED_PROTECTION_TYPE protectionType;

            // �p�X���[�h�����łɈÍ�������Ă���ꍇ�́A�ēx�Í������ׂ��ł͂Ȃ��B
            // �Í������ꂽ�p�X���[�h�́A�Ⴆ�΃^�[�~�i���E�T�[�r�X�ڑ����� 
            // CPUS_LOGON �V�i���I�� SetSerialization �Ŏ󂯎�邱�Ƃ��ł���B
            if (CredIsProtectedW(pwzPasswordCopy, &protectionType))
            {
                if (CredUnprotected != protectionType)
                {
                    bCredAlreadyEncrypted = true;
                }
            }
            // CPUS_CREDUI �V�i���I�ł́A�p�X���[�h���Í������ׂ��ł͂Ȃ��B 
            // �Ăяo�������Í������ꂽ�p�X���[�h��\�����Ă��邩�A�܂��͈����邩��m�邱�Ƃ͂ł��܂���B
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

        // ���ۂ̕������B�k�������ŏI�[���ꂽ������͊܂܂Ȃ��B
        size_t lenDomain = pchDomainEnd - pchDomainBegin + 1; 
        pszDomain = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenDomain + 1)));
        if (pszDomain != nullptr)
        {
            hr = StringCchCopyN(pszDomain, lenDomain + 1, pchDomainBegin, lenDomain);
            if (SUCCEEDED(hr))
            {
                // ���ۂ̕������B�k�������ŏI�[���ꂽ������͊܂܂Ȃ��B
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