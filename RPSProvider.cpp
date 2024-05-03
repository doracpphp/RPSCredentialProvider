#include <initguid.h>
#include "RPSProvider.h"
#include "RPSCredential.h"
#include "guid.h"

RPSProvider::RPSProvider() :
    _cRef(1),
    _pCredential(nullptr),
    _pCredProviderUserArray(nullptr),
    dwUserCount(0)
{
    DllAddRef();
}

RPSProvider::~RPSProvider()
{
    if (_pCredential != nullptr)
    {
        for (int i = 0; i < dwUserCount; i++) {
            if (_pCredential[i] != NULL) {
                _pCredential[i]->Release();
                _pCredential[i] = NULL;
            }
        }
    }
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    DllRelease();
}

// SetUsageScenarioは、後続の呼び出しでタイルを要求されるというプロバイダの合図である。
HRESULT RPSProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    // どのシナリオをサポートするかはここで決める。
    // E_NOTIMPLを返すと、呼び出し元は単にそのシナリオ用に設計されていないことを伝えます。
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // _fRecreateEnumeratedCredentialsが必要な理由は、
        // ICredentialProvider::SetUsageScenario()の後に
        // ICredentialProviderSetUserArray::SetUserArray()が呼び出されるからであり、
        // ICredentialProvider::GetCredentialCount()での列挙中に
        // ICredentialProviderUserArrayが必要だからである。
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization は、認証の試行に対して LogonUI に通常返される種類のバッファを取ります。 
// これは ICredentialProviderCredential::GetSerialization の逆です。
// GetSerialization は、クレデンシャルによって実装され、そのクレデンシャルをシリアライズします。 
// 代わりにSetSerializationはシリアライズを受け取り、タイルを作成するためにそれを使用します。
//
// SetSerializationは主に2つのシナリオで呼び出される。 
// 最初のシナリオは、credui のケースで、ユーザが OS に格納することを選択したクレデンシャルをタイルに事前投入する場合である。
// リモートクライアントがタイルにユーザー名を事前に入力したり、
// 場合によってはタイルを完全に入力し、UIを表示せずにログオンするためにタイルを使用したりしたい場合である。
//
// SetSerialization の例を見たい場合は、SampleCredentialProvider サンプルか SampleCredUICredentialProvider サンプルを参照してください。
//  [logonUIチームは、「これを基に構築された元のサンプルは、SetSerializationを持っていませんでした。 
// そして、SetSerializationがサンプルで持つのに十分重要であると判断したとき、
// それをメインのサンプルに統合するのは、結局、自明な作業量ではありませんでした。 
// 私たちは、SampleCredentialProviderからのSetSerializationの変更をこのサンプルに統合する作業を行うためにサンプルを保持するよりも、
// これらのサンプルを素早く皆さんに提供することの方が重要だと考えました]。

HRESULT RPSProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// コールバックを与えるためにLogonUIによって呼び出される。 
// プロバイダは、何らかのイベントで列挙したタイルのセットを
// 変更する必要が生じた場合、コールバックを使用することがよくあります。
HRESULT RPSProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    return E_NOTIMPL;
}

// ICredentialProviderEvents コールバックが無効になったときに LogonUI によって呼び出される。
HRESULT RPSProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// タイルのフィールド数を決定するためにLogonUIによって呼び出される。 
// これは、すべてのタイルが同じ数のフィールドを持つ必要があることを意味します。

HRESULT RPSProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = RFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT RPSProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < RFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// pdwCountに、現時点で表示したいタイルの数を設定する。
// pdwDefault に、デフォルトとして使用するタイルのインデックスを設定する。
// デフォルトのタイルは、デフォルトでズームビューに表示されるタイルです。
// 複数のプロバイダがデフォルトを指定した場合、最後に使用されたクレジットがデフォルトを選択します。
// pbAutoLogonWithDefaultがTRUEである場合、LogonUIは直ちに以下を呼び出します。
// デフォルトとして指定したクレデンシャルの GetSerialization を即座に呼び出し、
// それ以上の UI を表示することなく、そのクレデンシャルを認証に提出します。

HRESULT RPSProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = TRUE;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;

        //ICredentialProviderCredential2をリリースします
        if (_pCredential != nullptr)
        {
            for (int i = 0; i < dwUserCount; i++) {
                if (_pCredential[i] != NULL) {
                    _pCredential[i]->Release();
                    _pCredential[i] = NULL;
                }
            }
        }

        switch (_cpus)
        {
        case CPUS_LOGON:
        case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
        default:
            break;
        }
    }

    *pdwCount = dwUserCount;

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT RPSProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;

    if ((dwIndex < dwUserCount) && (ppcpc != NULL) && (_pCredential != NULL) && (_pCredential[dwIndex] != NULL))
    {
        hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// この関数は、SetUsageScenario が成功した後、LogonUI によって呼び出される。
// ログオン画面で列挙されるユーザーのリストで、User Array を設定します。
HRESULT RPSProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}


HRESULT RPSProvider::_EnumerateCredentials()
{
    HRESULT hr = E_UNEXPECTED;
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->GetCount(&dwUserCount);
        _pCredential = new(std::nothrow) RPSCredential*[dwUserCount];
        if (_pCredential != NULL)
        {
            for (int i = 0; i < dwUserCount; i++)
            {
                _pCredential[i] = new(std::nothrow)RPSCredential();
                if (_pCredential[i] != NULL)
                {
                    ICredentialProviderUser* pCredUser;
                    hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
                    if (SUCCEEDED(hr))
                    {
                        hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                        if (FAILED(hr))
                        {
                            for (int i2 = 0; i2 < dwUserCount; i2++) {
                                if (_pCredential[i2] != NULL) {
                                    _pCredential[i2]->Release();
                                    _pCredential = nullptr;
                                }
                            }
                        }
                        pCredUser->Release();
                    }
                }
            }
        }
    }
    return hr;
}

// プロバイダを作成するためのコード

HRESULT RPS_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    RPSProvider *pProvider = new(std::nothrow) RPSProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
