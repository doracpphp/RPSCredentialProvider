
#include <ntstatus.h>
#include "RPSCredential.h"
#include "guid.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

RPSCredential::RPSCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _dwComboIndex(0),
    _cpuHand(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    generateRPS();
}

RPSCredential::~RPSCredential()
{
    if (_rgFieldStrings[RFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[RFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[RFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[RFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}

HRESULT RPSCredential::generateRPS() {
    HRESULT hr = S_OK;
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) == 0) {
        return E_UNEXPECTED;
    }
    srand(ts.tv_nsec ^ ts.tv_sec);
    _cpuHand = rand() % 3;
    return hr;
}
// �n���ꂽ�t�B�[���h���� 1 �̃N���f���V���������������܂��B
HRESULT RPSCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    // �e�t�B�[���h�̃t�B�[���h�L�q�q���R�s�[����B����́A�N���f���V�������ǂ̂悤�ȗ��p�V�i���I�̂��߂�
    // �쐬���ꂽ���Ɋ�Â��ăt�B�[���h�L�q�q��ς������ꍇ�ɕ֗��ł��B
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // UI�̃e�L�X�g��ݒ肷��
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"����񂯂񃍃O�C��", &_rgFieldStrings[RFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[RFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"����񂯂񂷂�", &_rgFieldStrings[RFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"����񂯂�", &_rgFieldStrings[RFI_COMBOBOX]);
    }

    //https://learn.microsoft.com/ja-jp/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovideruser-getstringvalue
    if (SUCCEEDED(hr))
    {
        //�F�ؗp�̃��[�U�����擾
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
        //SID���擾
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI�́A�����ʒm����K�v������ꍇ�ɃR�[���o�b�N��^���邽�߂ɂ�����Ăяo���B
HRESULT RPSCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI�́A�R�[���o�b�N��������邱�Ƃ�`���邽�߂ɂ�����Ăяo���B
HRESULT RPSCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI�́A�^�C�����I�����ꂽ�i�Y�[�����ꂽ�j�Ƃ��ɂ��̊֐����Ăяo���B 
// �P�ɑI�����ꂽ��ԂɊ�Â��ăt�B�[���h��\���^��\���ɂ������ꍇ�́A�����ŉ�������K�v�͂Ȃ��B
// �������A�^�C�����I�����ꂽ�Ƃ��Ƀt�B�[���h�̓��e��ύX����ȂǁA�����ƕ��G�Ȃ��Ƃ��������ꍇ�́A�����ł�����s�����ƂɂȂ�B
HRESULT RPSCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// SetSelected�Ɠ��l�ɁALogonUI�́A�^�C�����I������Ă����Ƃ��ɂ�����Ăяo���܂��B
// �����ōs���ł���ʓI�Ȃ��Ɓi�ȉ��ōs���j�́A�p�X���[�h�E�t�B�[���h���������邱�Ƃł���B
HRESULT RPSCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[RFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[RFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[RFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[RFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[RFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[RFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, RFI_PASSWORD, _rgFieldStrings[RFI_PASSWORD]);
        }
    }

    return hr;
}

// �^�C���̓���̃t�B�[���h�̏����擾����B
// �^�C����\�����邽�߂̏����擾���邽�߂�logonUI�ɂ���ČĂяo�����B
HRESULT RPSCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// ppwsz ���C���f�b�N�X dwFieldID �̃t�B�[���h�̕�����l�ɐݒ肷��B
HRESULT RPSCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// ���[�U�[�^�C���ɕ\������摜���擾����
HRESULT RPSCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((RFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}


// Submit�{�^���̈ʒu�����߂�
HRESULT RPSCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (RFI_SUBMIT_BUTTON == dwFieldID)
    {
        // ComboBox�ׂ̗ɔz�u����
        *pdwAdjacentTo = RFI_COMBOBOX;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// �������l�Ƃ��Ď󂯎�邱�Ƃ��ł���t�B�[���h�̒l��ݒ肷��B
// ����́A���[�U�[���ҏW�t�B�[���h�ɓ��͂���ۂɁA�L�[�X�g���[�N���ƂɌĂяo����܂��B
HRESULT RPSCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// �`�F�b�N�{�b�N�X���`�F�b�N����Ă��邩�ǂ����A����т��̃��x����Ԃ��܂��B
// �g�p���Ȃ��̂�S_OK��Ԃ�
HRESULT RPSCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr = S_OK;
    return hr;
}

// �w�肳�ꂽ�`�F�b�N�{�b�N�X���`�F�b�N����Ă��邩�ǂ�����ݒ肵�܂��B
// �g�p���Ȃ��̂�S_OK��Ԃ�
HRESULT RPSCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr S_OK;
    return hr;
}

// �R���{�{�b�N�X�Ɋ܂܂��A�C�e���̐� (pcItems) �ƁA
// ���ݑI������Ă���A�C�e�� (pdwSelectedItem) ��Ԃ��܂�
HRESULT RPSCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// �C���f�b�N�X dwItem �̕����� (ppwszItem) �ŃR���{�{�b�N�X�𖄂߂邽�߂ɌJ��Ԃ��Ăяo����܂��B
HRESULT RPSCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Combobox��ύX�����ۂɌĂяo�����
HRESULT RPSCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        //_dwComboIndex�Ɍ��ݑI�����ꂽComboBox�̈ʒu������
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// ���[�U�[���R�}���h�����N���N���b�N�����Ƃ��ɌĂяo�����B
// �g�p���Ȃ��̂�S_OK��Ԃ�
HRESULT RPSCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;
    return hr;
}

// ���[�U�[���ƃp�X���[�h���A�������g�p�V�i���I�i���̃T���v���ł̓��O�I��/�A�����b�N�j�p�̃V���A���C�Y���ꂽ�N���f���V�����Ɏ��W���� 
// LogonUI �́A�����̃N���f���V�������V�X�e���ɓn���ă��O�I�����܂��B
HRESULT RPSCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    PWSTR pwzProtectedPassword;

    hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[RFI_PASSWORD], _cpus, &pwzProtectedPassword);
    if (SUCCEEDED(hr))
    {
        PWSTR pszDomain;
        PWSTR pszUsername;
        hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
        if (SUCCEEDED(hr))
        {
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;
            hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
            if (SUCCEEDED(hr))
            {
                // ���b�N�����ƃ��O�I���̗����̃V�i���I�ŁAKERB_INTERACTIVE_UNLOCK_LOGON ���g�p����B 
                // ����́A�N���W�b�g��ێ����邽�߂�KERB_INTERACTIVE_LOGON�ƁA�K�v�ɉ�����Winlogon�ɂ���Ė��߂���LUID���܂�ł���B
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_RPS;
                        // ���̎��_�ŁA�N���f���V�����̓��O�I���Ɏg�p�����V���A���C�Y���ꂽ�N���f���V�������쐬���܂����B
                        // ����� CPGSR_RETURN_CREDENTIAL_FINISHED �ɐݒ肷�邱�ƂŁA 
                        // logonUI �ɕK�v�ȏ�񂪂��ׂđ��������Ƃ�m�点�Ă���B
                        // ���O�I�����邽�߂Ɏg�p�����V���A���C�Y���ꂽ�N���f���V�������쐬�����B
                        // �V���A���C�Y���ꂽ�N���f���V�����̑��M�����݂Ȃ���΂Ȃ�Ȃ��B
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        switch (((int)_dwComboIndex - _cpuHand + 3) % 3) {
                        case 2:
                            break;
                        case 0:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"���������ł�", ppwszOptionalStatusText))) {
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                            }
                            break;
                        case 1:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"����񂯂�ɕ����܂���", ppwszOptionalStatusText))) {
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                            }
                            break;
                        default:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"�G���[", ppwszOptionalStatusText))) {
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                            }
                            break;
                        }
                    }
                }
            }
            generateRPS();
            CoTaskMemFree(pszDomain);
            CoTaskMemFree(pszUsername);
        }
        CoTaskMemFree(pwzProtectedPassword);
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

// ReportResult�͊��S�ɃI�v�V�����ł���B ���̖ړI�́A
// ���O�I���Ɏ��s�����ꍇ�ɕ\������镶����ƃA�C�R�����N���f���V�������J�X�^�}�C�Y�ł���悤�ɂ��邱�Ƃł���B 
// �Ⴆ�΁A�s���ȃ��[�U��/�p�X���[�h�̏ꍇ�ƃA�J�E���g�������ɂ��ꂽ�ꍇ�ɕ\�������G���[���J�X�^�}�C�Y���邱�Ƃɂ��܂����B
HRESULT RPSCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    if (E_UNEXPECTED == ntsStatus) {
        if (SUCCEEDED(SHStrDupW(L"����񂯂�ɕ����܂���", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    if (STATUS_LOGON_FAILURE == ntsStatus && STATUS_SUCCESS == ntsSubstatus) {
        if (SUCCEEDED(SHStrDupW(L"���[�U���������̓p�X���[�h���Ԉ���Ă��܂�.", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    else {
        if (SUCCEEDED(SHStrDupW(L"���O�C�����ł��܂���ł���", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    // If we failed the logon, try to erase the password field.
    if (FAILED(ntsStatus))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, RFI_PASSWORD, L"");
            //�Ăт���񂯂�̎�𐶐�����
            generateRPS();
        }
    }
    return S_OK;
}

// �N���f���V�����ɑΉ����郆�[�U�� SID ���擾���܂��B
HRESULT RPSCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // �N���f���V��������̃��[�U�E�^�C���Ɋ֘A�t�����Ă���ꍇ�́AppszSid �� NULL SID ���w�肵�� S_FALSE ��Ԃ��܂��B
    return hr;
}

// GetFieldOptions���g�p���āA�p�X���[�h�t�B�[���h�̃p�X���[�h���J�{�^���ƃ^�b�`�L�[�{�[�h�̎����N����L���ɂ��܂��B
HRESULT RPSCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == RFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    return S_OK;
}
