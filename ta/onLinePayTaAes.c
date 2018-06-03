
/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               onLinePayTaAes.c
 *
 * Filename      : onLinePayTaAes.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Fri 30 Oct 2015 12:40:02 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_CRYPTO_TA_AES_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "onLinePayTaAes.h"
#include "onLinePayTaDebug.h"
#include "onLinePayTaOther.h"
#include "onLinePayTaPbkdf2.h"




/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
int g_CryptoTaHandle_Aes(CHAR* pInput, UINT32 lenInput, CHAR* pOutput,
            EN_AES_OPERATION_ACTION active, EN_AES_MODE mode);
void g_CryptoTaHandle_GetRandomOne(CHAR* buf, UINT32 len);
void g_CryptoTaHandle_SaveRandomTwo(CHAR* buf, UINT32 len);
void g_CryptoTaHandle_GetRandomThree(CHAR* buf, UINT32 len);
void g_CryptoTaHandle_SetAesKey(void);




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
int l_CryptoTaAes_AesOper(AesOperation aesOper);
static void l_CryptoTaHandle_SetAes128Key(AesOperation* aesOper);
static void l_CryptoTaHandle_SetAesAction(AesOperation* aesOper, AesOperModeInfo modeInfo);





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
CHAR g_AesKeyBuf[32] = {0};
CHAR g_Aes128Key[] = {0x5f, 0x63, 0xf5, 0xad, 0x57, 0x69, 0xb6, 0x86, 0xe9, 0x5f, 0xc9, 0xc5, 0xe7, 0xda, 0xfb, 0x98};
CHAR g_Aes128Iv[] = {0x91, 0x7a, 0x18, 0x27, 0x6d, 0xc6, 0x6d, 0xbf, 0x3d, 0xf2, 0xad, 0x96, 0xe8, 0xeb, 0x6b, 0x16};

CHAR g_RandomOne[16] = 
{
    0x11, 0x02, 0x0a, 0x0f, 0x05, 0x43, 0x74, 0x9a,
    0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x22, 0x44, 0x07
};
CHAR g_RandomTwo[16] = 
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11
};
CHAR g_RandomThree[16] = 
{
    0x11, 0x02, 0x0a, 0x0f, 0x05, 0x43, 0x74, 0x9a,
    0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x22, 0x44, 0x07
};






/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
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
int l_CryptoTaAes_AesOper(AesOperation aesOper)
{
    TEE_OperationHandle l_pOperation = NULL;
    TEE_ObjectHandle l_pKeyObj = NULL;
    TEE_Attribute l_pAttr;
    CHAR* l_pInbuf = aesOper.inBuf;
    CHAR* l_pOutbuf = aesOper.outBuf;
    UINT32 l_dataLen = aesOper.dataLen;
    TEE_Result l_RetVal = TEE_FAIL;
    int l_Result = FAIL;


    TF("The Aes operation information just like follow:\n");
    TF("Aes key=\n");
    g_TA_Printf(aesOper.key, 16);
    TF("IV=\n");
    g_TA_Printf(aesOper.iv, aesOper.ivLen);
    TF("Algorith= 0x%x\n", aesOper.algorithmId);
    TF("Mode=0x%x\n", aesOper.operMode);
    TF("Raw just like follow:\n");
    g_TA_Printf(aesOper.inBuf, aesOper.dataLen);

    /**1) Allocate the operation handle */
    l_RetVal = TEE_AllocateOperation(&l_pOperation, aesOper.algorithmId, aesOper.operMode, aesOper.keyLen);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }

    TF("Allocate object\n");
    /**2) Allocate the object handle */
    l_RetVal = TEE_AllocateTransientObject(TEE_TYPE_AES, aesOper.keyLen, &l_pKeyObj);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }   

    TF("Init attribute\n");
    /**3) Set the key object parameter */
    TEE_InitRefAttribute(&l_pAttr, TEE_ATTR_SECRET_VALUE, aesOper.key, 16);
    l_RetVal = TEE_PopulateTransientObject(l_pKeyObj, &l_pAttr, 1);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }

    TF("Set key\n");
    /**4) Assemble aes operation handle */
    l_RetVal = TEE_SetOperationKey(l_pOperation, l_pKeyObj);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_2;
    }

    TF("Init cipher\n");
    /**5) Initialze cipher operation */
    TEE_CipherInit(l_pOperation, aesOper.iv, aesOper.ivLen);


#if 0
    /**6) Update the input data into the buffer for do AES operation */
    while(true)
    {
        if(SIZE_OF_AES128_BLOCK_LEN == l_dataLen)
        {
            break;
        }
        else
        {
            if(0U != (l_dataLen / SIZE_OF_AES128_BLOCK_LEN))
            {
                /* Do update operation */
                l_RetVal = TEE_CipherUpdate(l_pOperation, l_pInbuf, SIZE_OF_AES128_BLOCK_LEN,
                                              l_pOutbuf, SIZE_OF_AES128_BLOCK_LEN);
                if(TEE_SUCCESS != l_RetVal)
                {
                    l_Result = FAIL;
                    goto cleanup_2;
                }

                /* Move the buffer point & length of remainder data */
                l_pInbuf = &(l_pInbuf[SIZE_OF_AES128_BLOCK_LEN]);
                l_pOutbuf = &(l_pOutbuf[SIZE_OF_AES128_BLOCK_LEN]);
                l_dataLen = l_dataLen - SIZE_OF_AES128_BLOCK_LEN;
            }
            else
            {
                break;
            }
            
        }
    }
#endif

    TF("Do final cipher\n");
    /** 6) Do the final AES operation */
    l_RetVal = TEE_CipherDoFinal(l_pOperation, l_pInbuf, l_dataLen, l_pOutbuf, &l_dataLen);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
    }
    else
    {
        l_Result = OK;
    }

    TF("The aes operation out put just like follow:\n");
    g_TA_Printf(aesOper.outBuf, aesOper.dataLen);



cleanup_2:
    TEE_FreeOperation(l_pOperation);
cleanup_1:
    return l_Result;
}


static void l_CryptoTaHandle_SetAes128Key(AesOperation* aesOper)
{
    aesOper->key = g_Aes128Key;
    aesOper->iv = g_Aes128Iv;
    aesOper->keyLen = 128U;
    aesOper->ivLen = 16U;
}

static void l_CryptoTaHandle_SetAesAction(AesOperation* aesOper, AesOperModeInfo modeInfo)
{
    switch(modeInfo.active)
    {
        case EN_OP_AES_ENCRYPT:
            aesOper->operMode = TEE_MODE_ENCRYPT;
            break;
        case EN_OP_AES_DECRYPT:
            aesOper->operMode = TEE_MODE_DECRYPT;
            break;
        default:
            break;
    }

    switch(modeInfo.mode)
    {
        case EN_MODE_CBC:
            aesOper->algorithmId= TEE_ALG_AES_CBC_NOPAD;
            break;
        case EN_MODE_ECB:
            aesOper->algorithmId = TEE_ALG_AES_ECB_NOPAD;
            break;
        case EN_MODE_CTR:
            aesOper->algorithmId = TEE_ALG_AES_CTR;
            break;
        case EN_MODE_CBC_CTS:
            aesOper->algorithmId = TEE_ALG_AES_CTS;
            break;
        default:
            break;
    }
}



int g_CryptoTaHandle_Aes(CHAR* pInput, UINT32 lenInput, CHAR* pOutput,
        EN_AES_OPERATION_ACTION active, EN_AES_MODE mode)
{    
    AesOperation l_aesOper;    
    AesOperModeInfo l_pAesModeInfo;    
    CHAR test[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};    
  
    TF("Start to do AES operation!!!!\n");    

    /**1) Get the sha mode, input data info & output info */    
    l_pAesModeInfo.active = active;    
    l_pAesModeInfo.mode = mode;    
    l_aesOper.inBuf = pInput;    
    l_aesOper.outBuf = pOutput;    
    l_aesOper.dataLen = lenInput;    
    TEE_MemMove(l_aesOper.outBuf, test, sizeof(test));    

    /**2) Put key & IV info into variable */    
    l_CryptoTaHandle_SetAes128Key(&l_aesOper); 
    TF("AES key INFO:\n");
    g_TA_Printf(l_aesOper.key, 16U);
    g_TA_Printf(l_aesOper.iv, 16U);

    /**3) Set the algorithm & mode */    
    l_CryptoTaHandle_SetAesAction(&l_aesOper, l_pAesModeInfo);    
    TF("ID: 0x%x, mode: 0x%x\n", l_aesOper.algorithmId, l_aesOper.operMode);        

    /**4) Do AES operation */    
    l_CryptoTaAes_AesOper(l_aesOper);    

    return OK;
}


void g_CryptoTaHandle_SetAesKey(void)
{
    CHAR l_SalBuf[64] = {0};
    UINT32 l_lenSalt = 0U;

    /** 8) Cauculate AES key for exchanging of data between client and server */
    l_lenSalt = g_CryptoTaOther_mixData(g_RandomTwo, sizeof(g_RandomTwo), 
        g_RandomThree, sizeof(g_RandomThree), l_SalBuf);
    g_CryptoTaPbkdf_PBKDF2(g_RandomOne, sizeof(g_RandomOne), l_SalBuf, l_lenSalt,
                16, 32, g_AesKeyBuf);
    TF("Calculate out AES key ad IV just like below:\n");
    g_TA_Printf(g_AesKeyBuf, 32);
    TEE_MemMove(g_Aes128Key, g_AesKeyBuf, 16);
    TEE_MemMove(g_Aes128Iv, &(g_AesKeyBuf[16]), 16);
}

void g_CryptoTaHandle_GetRandomOne(CHAR* buf, UINT32 len)
{
    //g_CryptoTaOther_Random(len, g_RandomOne); /* Generate first random data */
    TEE_MemMove(buf, g_RandomOne, len);
}

void g_CryptoTaHandle_SaveRandomTwo(CHAR* buf, UINT32 len)
{
    TEE_MemMove(g_RandomTwo, buf, len);
}

void g_CryptoTaHandle_GetRandomThree(CHAR* buf, UINT32 len)
{
    //g_CryptoTaOther_Random(len, g_RandomThree); /* Generate third random data */
    TEE_MemMove(buf, g_RandomThree, len);
}




/**
 * @}
 */
