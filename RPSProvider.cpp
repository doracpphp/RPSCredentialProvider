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

// SetUsageScenario�́A�㑱�̌Ăяo���Ń^�C����v�������Ƃ����v���o�C�_�̍��}�ł���B
HRESULT RPSProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    // �ǂ̃V�i���I���T�|�[�g���邩�͂����Ō��߂�B
    // E_NOTIMPL��Ԃ��ƁA�Ăяo�����͒P�ɂ��̃V�i���I�p�ɐ݌v����Ă��Ȃ����Ƃ�`���܂��B
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // _fRecreateEnumeratedCredentials���K�v�ȗ��R�́A
        // ICredentialProvider::SetUsageScenario()�̌��
        // ICredentialProviderSetUserArray::SetUserArray()���Ăяo����邩��ł���A
        // ICredentialProvider::GetCredentialCount()�ł̗񋓒���
        // ICredentialProviderUserArray���K�v������ł���B
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

// SetSerialization �́A�F�؂̎��s�ɑ΂��� LogonUI �ɒʏ�Ԃ�����ނ̃o�b�t�@�����܂��B 
// ����� ICredentialProviderCredential::GetSerialization �̋t�ł��B
// GetSerialization �́A�N���f���V�����ɂ���Ď�������A���̃N���f���V�������V���A���C�Y���܂��B 
// �����SetSerialization�̓V���A���C�Y���󂯎��A�^�C�����쐬���邽�߂ɂ�����g�p���܂��B
//
// SetSerialization�͎��2�̃V�i���I�ŌĂяo�����B 
// �ŏ��̃V�i���I�́Acredui �̃P�[�X�ŁA���[�U�� OS �Ɋi�[���邱�Ƃ�I�������N���f���V�������^�C���Ɏ��O��������ꍇ�ł���B
// �����[�g�N���C�A���g���^�C���Ƀ��[�U�[�������O�ɓ��͂�����A
// �ꍇ�ɂ���Ă̓^�C�������S�ɓ��͂��AUI��\�������Ƀ��O�I�����邽�߂Ƀ^�C�����g�p�����肵�����ꍇ�ł���B
//
// SetSerialization �̗���������ꍇ�́ASampleCredentialProvider �T���v���� SampleCredUICredentialProvider �T���v�����Q�Ƃ��Ă��������B
//  [logonUI�`�[���́A�u�������ɍ\�z���ꂽ���̃T���v���́ASetSerialization�������Ă��܂���ł����B 
// �����āASetSerialization���T���v���Ŏ��̂ɏ\���d�v�ł���Ɣ��f�����Ƃ��A
// ��������C���̃T���v���ɓ�������̂́A���ǁA�����ȍ�Ɨʂł͂���܂���ł����B 
// �������́ASampleCredentialProvider�����SetSerialization�̕ύX�����̃T���v���ɓ��������Ƃ��s�����߂ɃT���v����ێ���������A
// �����̃T���v����f�����F����ɒ񋟂��邱�Ƃ̕����d�v���ƍl���܂���]�B

HRESULT RPSProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// �R�[���o�b�N��^���邽�߂�LogonUI�ɂ���ČĂяo�����B 
// �v���o�C�_�́A���炩�̃C�x���g�ŗ񋓂����^�C���̃Z�b�g��
// �ύX����K�v���������ꍇ�A�R�[���o�b�N���g�p���邱�Ƃ��悭����܂��B
HRESULT RPSProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    return E_NOTIMPL;
}

// ICredentialProviderEvents �R�[���o�b�N�������ɂȂ����Ƃ��� LogonUI �ɂ���ČĂяo�����B
HRESULT RPSProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// �^�C���̃t�B�[���h�������肷�邽�߂�LogonUI�ɂ���ČĂяo�����B 
// ����́A���ׂẴ^�C�����������̃t�B�[���h�����K�v�����邱�Ƃ��Ӗ����܂��B

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

// pdwCount�ɁA�����_�ŕ\���������^�C���̐���ݒ肷��B
// pdwDefault �ɁA�f�t�H���g�Ƃ��Ďg�p����^�C���̃C���f�b�N�X��ݒ肷��B
// �f�t�H���g�̃^�C���́A�f�t�H���g�ŃY�[���r���[�ɕ\�������^�C���ł��B
// �����̃v���o�C�_���f�t�H���g���w�肵���ꍇ�A�Ō�Ɏg�p���ꂽ�N���W�b�g���f�t�H���g��I�����܂��B
// pbAutoLogonWithDefault��TRUE�ł���ꍇ�ALogonUI�͒����Ɉȉ����Ăяo���܂��B
// �f�t�H���g�Ƃ��Ďw�肵���N���f���V������ GetSerialization �𑦍��ɌĂяo���A
// ����ȏ�� UI ��\�����邱�ƂȂ��A���̃N���f���V������F�؂ɒ�o���܂��B

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

        //ICredentialProviderCredential2�������[�X���܂�
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

// ���̊֐��́ASetUsageScenario ������������ALogonUI �ɂ���ČĂяo�����B
// ���O�I����ʂŗ񋓂���郆�[�U�[�̃��X�g�ŁAUser Array ��ݒ肵�܂��B
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

// �v���o�C�_���쐬���邽�߂̃R�[�h

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
