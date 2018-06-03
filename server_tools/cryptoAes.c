/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    This program contains proprietary information which is a trade                    */
/*    secret of whaley Co., Ltd.and also is protected as an   unpublished               */
/*    work under applicable Copyright laws. Recipient is to retain this                 */
/*    program in confidence and is not permitted to use or make copies thereof          */
/*    other than as permitted in a written agreement written agreement with             */
/*    whaley Co., Ltd.                                                                  */
/*                                                                                      */
/*    All rights reserved. whaley Co., Ltd.                                             */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               cryptoAes.c
 *
 * Filename      : cryptoAes.c
 * Programmer(s) : system BSP
 * Filename      : cryptoAes.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:01:41 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_AES_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include "cryptoDebug.h"
#include "cryptoAes.h"



/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/

static CHAR g_AesKey[16] = {0x5f, 0x63, 0xf5, 0xad, 0x57, 0x69, 0xb6, 0x86, 0xe9, 0x5f, 0xc9, 0xc5, 0xe7, 0xda, 0xfb, 0x98};

static CHAR g_AesIv[16]= {0x91, 0x7a, 0x18, 0x27, 0x6d, 0xc6, 0x6d, 0xbf, 0x3d, 0xf2, 0xad, 0x96, 0xe8, 0xeb, 0x6b, 0x16};



/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/

void l_CryptoAes_InitCtr(CtrState* state, CHAR* iv)
{
    state->num = 0;
    memset(state->ecount, 0, 16);
    memset(state->ivec, 0, 16);
    memcpy(state->ivec, iv, 16);
}



void l_CryptoAes_EcbOperation(AES_KEY* aesKey, CHAR* pInput, UINT32 inLen, CHAR* pOutput, int enc)
{
    UINT32 l_loop = 0U;
    UINT32 l_Index = 0U;
    l_loop = inLen / 16U;
    for(l_Index = 0U; l_Index < l_loop; l_Index++)
    {
        AES_ecb_encrypt((pInput + (l_Index * 16U)), (pOutput + (l_Index * 16U)), aesKey, enc);
    }
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handle command.
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
void g_CryptoAes_encrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput)
{
    int l_Result = 0;
    AES_KEY ass_key;
    CtrState l_State;
    
    memset(&ass_key, 0, sizeof(AES_KEY));
    g_Debug_Printf(g_AesKey, 16);
    g_Debug_Printf(g_AesIv, 16);
    l_Result = AES_set_encrypt_key((const char *)g_AesKey, 128, &ass_key);
    if(0 > l_Result)
    {
        printf("ERROR: set encrypt key error!!!\n");
    }
    else
    {

        if(EN_MODE_CTR == aesMode)
        {
            l_CryptoAes_InitCtr(&l_State, g_AesIv);
        }
        
        switch(aesMode)
        {
            case EN_MODE_CBC:
                AES_cbc_encrypt(pInput, pOutput, inLen, &ass_key, g_AesIv, AES_ENCRYPT);
                break;
            case EN_MODE_ECB:
                l_CryptoAes_EcbOperation(&ass_key, pInput, inLen, pOutput, AES_ENCRYPT);
                break; 
            case EN_MODE_CTR:
                AES_ctr128_encrypt(pInput, pOutput, inLen, &ass_key, l_State.ivec, l_State.ecount, &(l_State.num));
                break;
            case EN_MODE_CBC_CTS:
                break;
            default:
                printf("ERROR: input invalid aes mode!!!\n");
                break;  
        }
    }
}


UINT32 l_CryptoTaOther_mixData(CHAR* oneBuf, UINT32 oneLen, CHAR* twoBuf, UINT32 twoLen, CHAR* pOutBuf)
{
    UINT32 l_loopNum = twoLen;
    UINT32 l_Index = 0U;
    CHAR* l_pTem = oneBuf;
    
    if(oneLen <= twoLen)
    {
        l_loopNum = oneLen;
        l_pTem = twoBuf;
    }

    for(l_Index = 0U; l_Index < l_loopNum; l_Index++)
    {
        pOutBuf[l_Index] = oneBuf[l_Index];
        pOutBuf[(l_Index * 2U) + 1] = twoBuf[l_Index];
    }

    memcpy(&(pOutBuf[l_loopNum * 2U]), &(l_pTem[l_loopNum]), (twoLen - l_loopNum + 1));

    return (oneLen + twoLen);
}



void g_CryptoAes_SetKey(CHAR* randomOne, CHAR* randomTwo, CHAR* randomThree)
{
    UINT32 l_lenSalt = 0U;
    CHAR l_SalBuf[64] = {0};
    CHAR l_buf[32] = {0};
    
    l_lenSalt = l_CryptoTaOther_mixData(randomTwo, 16, 
        randomThree, 16, l_SalBuf);

    g_CryptoPbkdf_PbkdfOperation(randomOne, 16, l_SalBuf, l_lenSalt, 16, 32, l_buf);
    TF("OutPut ASE key&IV just like below:\n");
    g_Debug_Printf(l_buf, 32);
    memcpy(g_AesKey, l_buf, 16);
    memcpy(g_AesIv, &(l_buf[16]), 16);

}

/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handle command.
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
void g_CryptoAes_decrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput)
{
    int l_Result = 0;
    AES_KEY ass_key;
    CtrState l_State;
    
    memset(&ass_key, 0, sizeof(AES_KEY));
    if(EN_MODE_CTR == aesMode)
    {
        l_Result = AES_set_encrypt_key((const char *)g_AesKey, 128, &ass_key);
    }
    else
    {
        l_Result = AES_set_decrypt_key((const char *)g_AesKey, 128, &ass_key);
    }
    
    if(0 > l_Result)
    {
        printf("ERROR: set encrypt key error!!!\n");

    }
    else
    {
        if(EN_MODE_CTR == aesMode)
        {
            l_CryptoAes_InitCtr(&l_State, g_AesIv);
        }

        switch(aesMode)
        {
            case EN_MODE_CBC:
                AES_cbc_encrypt(pInput, pOutput, inLen, &ass_key, g_AesIv, AES_DECRYPT);
                break;
            case EN_MODE_ECB:
                l_CryptoAes_EcbOperation(&ass_key, pInput, inLen, pOutput, AES_DECRYPT);
                break; 
            case EN_MODE_CTR:
                AES_ctr128_encrypt(pInput, pOutput, inLen, &ass_key, l_State.ivec, l_State.ecount, &(l_State.num));
                break;
            case EN_MODE_CBC_CTS:
                break;
            default:
                printf("ERROR: input invalid aes mode!!!\n");
                break;  
        }
    }
}
















/**
 * @}
 */
