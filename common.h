#pragma once
#include "helpers.h"

// Credential Providerのタイルの各フィールドのインデックス。

enum RPS_FIELD_ID
{
    RFI_TILEIMAGE         = 0,
    RFI_LARGE_TEXT        = 1,
    RFI_PASSWORD          = 2,
    RFI_SUBMIT_BUTTON     = 3,
    RFI_COMBOBOX          = 4,
    RFI_NUM_FIELDS        = 5,
};

// 最初の値はタイルがいつ表示されているか（選択されているか、選択されていないか）を示し、
// 2番目の値はフィールドが有効になっているか、キーフォーカスがあるかなどを示す。

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// Credential Providerは、フィールド状態のペアとフィールド記述子のさまざまな
// 組み合わせでクレデンシャルをセットアップしたい場合があるため、これら2つの配列は分離されている。

// フィールド状態の値は、フィールドが選択されたタイル、選択解除されたタイル、またはその両方に表示されるかどうかを示す。
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_COMBOBOX
};

// アンロックとログオンのフィールド記述子。
// 最初のフィールドはフィールドのインデックスである。
// 2番目はフィールドのタイプである。
// 3番目はフィールドの名前であり、フィールドに表示される値ではない。
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { RFI_TILEIMAGE,     CPFT_TILE_IMAGE,    L"Image",  CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { RFI_LARGE_TEXT,    CPFT_LARGE_TEXT,    L"じゃんけんログイン"},
    { RFI_PASSWORD,      CPFT_PASSWORD_TEXT, L"パスワード"},
    { RFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"じゃんけんする" },
    { RFI_COMBOBOX,      CPFT_COMBOBOX,      L"Combobox" },
};

static const PWSTR s_rgComboBoxStrings[] =
{
    L"グー✊",
    L"チョキ✌",
    L"パー✋",
};