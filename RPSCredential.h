#pragma once
#define _CRT_RAND_S


#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include "common.h"
#include "dll.h"
#include <stdlib.h>

#define IDB_TILE_IMAGE     101

class RPSCredential : public ICredentialProviderCredential2, ICredentialProviderCredentialWithFieldOptions
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(RPSCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            QITABENT(RPSCredential, ICredentialProviderCredential2), // IID_ICredentialProviderCredential2
            QITABENT(RPSCredential, ICredentialProviderCredentialWithFieldOptions), //IID_ICredentialProviderCredentialWithFieldOptions
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);


    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid);

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID,
                                   _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo);

  public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                       _In_ FIELD_STATE_PAIR const *rgfsp,
                       _In_ ICredentialProviderUser *pcpUser);
    RPSCredential();

  private:

    virtual ~RPSCredential(); 
    HRESULT generateRPS();
    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;                                          // �񋓂��ꂽ�g�p�V�i���I
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[RFI_NUM_FIELDS];    // �^�C���̊e�t�B�[���h�̌^�Ɩ��O��ێ�����z��
    FIELD_STATE_PAIR                        _rgFieldStatePairs[RFI_NUM_FIELDS];             // �^�C���̊e�t�B�[���h�̏�Ԃ�ێ�����z��
    PWSTR                                   _rgFieldStrings[RFI_NUM_FIELDS];                // �e�t�B�[���h�̕�����l��ێ�����z��B�����_rgCredProvFieldDescriptors�ŕێ������t�B�[���h�̖��O�Ƃ͈قȂ�܂�
    PWSTR                                   _pszUserSid;
    PWSTR                                   _pszQualifiedUserName;                          // �F�؃o�b�t�@���p�b�N���邽�߂Ɏg�p����郆�[�U�[��
    ICredentialProviderCredentialEvents2*    _pCredProvCredentialEvents;                    // �t�B�[���h�̍X�V
    DWORD                                   _dwComboIndex;                                  //�R���{�{�b�N�X�̌��݂̃C���f�b�N�X��ێ�
    DWORD                                   _cpuHand;
};
