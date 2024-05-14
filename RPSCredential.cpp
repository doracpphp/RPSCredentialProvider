
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
// 渡されたフィールド情報で 1 つのクレデンシャルを初期化します。
HRESULT RPSCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    // 各フィールドのフィールド記述子をコピーする。これは、クレデンシャルがどのような利用シナリオのために
    // 作成されたかに基づいてフィールド記述子を変えたい場合に便利です。
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // UIのテキストを設定する
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"じゃんけんログイン", &_rgFieldStrings[RFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[RFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"じゃんけんする", &_rgFieldStrings[RFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"じゃんけん", &_rgFieldStrings[RFI_COMBOBOX]);
    }

    //https://learn.microsoft.com/ja-jp/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovideruser-getstringvalue
    if (SUCCEEDED(hr))
    {
        //認証用のユーザ名を取得
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
        //SIDを取得
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUIは、何か通知する必要がある場合にコールバックを与えるためにこれを呼び出す。
HRESULT RPSCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUIは、コールバックを解放することを伝えるためにこれを呼び出す。
HRESULT RPSCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUIは、タイルが選択された（ズームされた）ときにこの関数を呼び出す。 
// 単に選択された状態に基づいてフィールドを表示／非表示にしたい場合は、ここで何もする必要はない。
// しかし、タイルが選択されたときにフィールドの内容を変更するなど、もっと複雑なことをしたい場合は、ここでそれを行うことになる。
HRESULT RPSCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// SetSelectedと同様に、LogonUIは、タイルが選択されていたときにこれを呼び出します。
// ここで行う最も一般的なこと（以下で行う）は、パスワード・フィールドを消去することである。
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

// タイルの特定のフィールドの情報を取得する。
// タイルを表示するための情報を取得するためにlogonUIによって呼び出される。
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

// ppwsz をインデックス dwFieldID のフィールドの文字列値に設定する。
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

// ユーザータイルに表示する画像を取得する
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


// Submitボタンの位置を決める
HRESULT RPSCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (RFI_SUBMIT_BUTTON == dwFieldID)
    {
        // ComboBoxの隣に配置する
        *pdwAdjacentTo = RFI_COMBOBOX;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// 文字列を値として受け取ることができるフィールドの値を設定する。
// これは、ユーザーが編集フィールドに入力する際に、キーストロークごとに呼び出されます。
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

// チェックボックスがチェックされているかどうか、およびそのラベルを返します。
// 使用しないのでS_OKを返す
HRESULT RPSCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr = S_OK;
    return hr;
}

// 指定されたチェックボックスがチェックされているかどうかを設定します。
// 使用しないのでS_OKを返す
HRESULT RPSCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr S_OK;
    return hr;
}

// コンボボックスに含まれるアイテムの数 (pcItems) と、
// 現在選択されているアイテム (pdwSelectedItem) を返します
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

// インデックス dwItem の文字列 (ppwszItem) でコンボボックスを埋めるために繰り返し呼び出されます。
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

// Comboboxを変更した際に呼び出される
HRESULT RPSCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        //_dwComboIndexに現在選択されたComboBoxの位置を入れる
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// ユーザーがコマンドリンクをクリックしたときに呼び出される。
// 使用しないのでS_OKを返す
HRESULT RPSCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;
    return hr;
}

// ユーザー名とパスワードを、正しい使用シナリオ（このサンプルではログオン/アンロック）用のシリアライズされたクレデンシャルに収集する 
// LogonUI は、これらのクレデンシャルをシステムに渡してログオンします。
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
                // ロック解除とログオンの両方のシナリオで、KERB_INTERACTIVE_UNLOCK_LOGON を使用する。 
                // これは、クレジットを保持するためのKERB_INTERACTIVE_LOGONと、必要に応じてWinlogonによって埋められるLUIDを含んでいる。
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_RPS;
                        // この時点で、クレデンシャルはログオンに使用されるシリアライズされたクレデンシャルを作成しました。
                        // これを CPGSR_RETURN_CREDENTIAL_FINISHED に設定することで、 
                        // logonUI に必要な情報がすべて揃ったことを知らせている。
                        // ログオンするために使用されるシリアライズされたクレデンシャルを作成した。
                        // シリアライズされたクレデンシャルの送信を試みなければならない。
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        switch (((int)_dwComboIndex - _cpuHand + 3) % 3) {
                        case 2:
                            break;
                        case 0:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"引き分けです", ppwszOptionalStatusText))) {
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                            }
                            break;
                        case 1:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"じゃんけんに負けました", ppwszOptionalStatusText))) {
                                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                            }
                            break;
                        default:
                            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                            if (SUCCEEDED(SHStrDupW(L"エラー", ppwszOptionalStatusText))) {
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

// ReportResultは完全にオプションである。 その目的は、
// ログオンに失敗した場合に表示される文字列とアイコンをクレデンシャルがカスタマイズできるようにすることである。 
// 例えば、不正なユーザ名/パスワードの場合とアカウントが無効にされた場合に表示されるエラーをカスタマイズすることにしました。
HRESULT RPSCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    if (E_UNEXPECTED == ntsStatus) {
        if (SUCCEEDED(SHStrDupW(L"じゃんけんに負けました", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    if (STATUS_LOGON_FAILURE == ntsStatus && STATUS_SUCCESS == ntsSubstatus) {
        if (SUCCEEDED(SHStrDupW(L"ユーザ名もしくはパスワードが間違っています.", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    else {
        if (SUCCEEDED(SHStrDupW(L"ログインができませんでした", ppwszOptionalStatusText))) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }
    // If we failed the logon, try to erase the password field.
    if (FAILED(ntsStatus))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, RFI_PASSWORD, L"");
            //再びじゃんけんの手を生成する
            generateRPS();
        }
    }
    return S_OK;
}

// クレデンシャルに対応するユーザの SID を取得します。
HRESULT RPSCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // クレデンシャルが空のユーザ・タイルに関連付けられている場合は、ppszSid に NULL SID を指定して S_FALSE を返します。
    return hr;
}

// GetFieldOptionsを使用して、パスワードフィールドのパスワード公開ボタンとタッチキーボードの自動起動を有効にします。
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
