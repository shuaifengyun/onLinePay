/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               onLinePayTaHandle.c
 *
 * Filename      : onLinePayTaHandle.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.com
 * Create Time   : Fri 30 Oct 2015 12:41:17 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_CRYPTO_TA_HANDLE_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "onLinePayTaHandle.h"
#include "onLinePayTaAes.h"
#include "onLinePayTaDebug.h"
#include "onLinePayTaHash.h"
#include "onLinePayTaOther.h"
#include "onLinePayTaPbkdf2.h"
#include "onLinePayTaRsa.h"




/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
int g_OnLinePayTaHandle_HandshakeOne(uint32_t paramTypes, TEE_Param params[4]);
int g_OnLinePayTaHandle_HandshakeTwo(uint32_t paramTypes, TEE_Param params[4]);
int g_OnLinePayTaHandle_HandshakeThree(uint32_t paramTypes, TEE_Param params[4]);
int g_OnLinePayTaHandle_pay(uint32_t paramTypes, TEE_Param params[4]);
int g_OnLinePayTaHandle_payOver(uint32_t paramTypes, TEE_Param params[4]);



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
UINT32 l_OnLinePayTaHandle_PackageHandshakeOne(CHAR* pBuf);
UINT32 l_OnLinePayTaHandle_PackageHandshakeThree(CHAR* pBuf);
UINT32 l_OnLinePayTaHandle_PackagePayOper(CHAR* pBuf);
int l_OnLinePayTaHandle_CheckHandshakeTwo(UINT32 inLen, CHAR* pInput);
int l_OnLinePayTaHandle_CheckPayOver(UINT32 inLen, CHAR* pInput);





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/










OnLinePayData g_OnLinePayData;  //Variable for saving data which will be sent to service
CHAR g_DefHandShakeOne[] = "!Data for handshake one!";
CHAR g_DefHandShakeTwo[] = "@Data for handshake two@";
CHAR g_DefHandShakeThree[] = "Data for handshake three";
CHAR g_DefPayReq[] = "###Requestion of on line pay operation##";
CHAR g_PayOperComplete[] = "&&On line pay execute completely";


CHAR g_KeyAlgorithm = 0x00;
UINT32 g_lenOfDataSection = 0x00U;

/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for package first handshake data.
 * @param   pBuf           [IN/OUT] Buffer for saving packaged data
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     l_Ret
 * @retval     return length of valid data
 *
 *
 */
UINT32 l_OnLinePayTaHandle_PackageHandshakeOne(CHAR* pBuf)
{
    UINT32 l_Ret = 0U;
    UINT32 l_pubKeyLen = 0U;
    HandshakeData l_HandData;   
    UINT32 l_RandomLen = 16U;

    /** 1) Clean buffer */
    TEE_MemFill(&g_OnLinePayData, 0, sizeof(OnLinePayData) - 256);

    /** 2) Assemble data of data section */
    l_HandData.mDataOne = g_DefHandShakeOne;
    l_HandData.mLenOne = sizeof(g_DefHandShakeOne) - 1;

    /** 3) Package plaintext */
    /** 3.1) Package header section */
    g_OnLinePayData.mHeaderSection.mVersion[0] = PROTOCOL_VERSION;  //Version of data
    g_OnLinePayData.mHeaderSection.mVersion[1] = ALGORITHM_VERSION;  // use RSA2048-SHA1-PKCS1 to sign data
    g_OnLinePayData.mHeaderSection.mFrom = DATA_FROM_CLIENT;    // Data from Client
    g_OnLinePayData.mHeaderSection.mTo = DATA_TO_SERVICE;      // Data to service
    g_OnLinePayData.mHeaderSection.mNum = FLAG_HANDSHAKE_KEY;

    /** 3.2) Package data section */
    g_OnLinePayData.mDataSection.mPurpose = PURPOSE_FOR_HANDSHAKE_ONE;
    g_OnLinePayData.mDataSection.mLength = l_HandData.mLenOne + l_RandomLen + 8U;
    g_OnLinePayData.mDataSection.mPdata = (CHAR*)(&l_HandData);
  
    /** 4) Copy header section data into buffer */
    l_Ret = sizeof(OnLinePayHeaderSection);    //Length of header + mPurpose + mLength
    TEE_MemMove(pBuf, &g_OnLinePayData, l_Ret);

    /** 5) Copy value of purpose into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mPurpose), sizeof(UINT16));
    l_Ret = l_Ret + sizeof(UINT16);

    /** 6) Copy length of data section into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mLength), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 7) Copy length of default data */
    TEE_MemMove(&(pBuf[l_Ret]), &(l_HandData.mLenOne), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 8) Copy default data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), g_DefHandShakeOne, sizeof(g_DefHandShakeOne) - 1);
    l_Ret = l_Ret + sizeof(g_DefHandShakeOne) -1;

    /** 9) Put length of random into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &l_RandomLen, sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 10) Copy ramdone one into buffer */
    g_CryptoTaHandle_GetRandomOne(&(pBuf[l_Ret]), 16);
    l_Ret = l_Ret + 16;
    
    /** 11) package public key into data section */
    l_pubKeyLen = g_CryptoTaHandle_PickPublicKey(&(pBuf[l_Ret]));
    l_Ret = l_Ret + l_pubKeyLen;

    /** 7) Return length of plain text data */
    return l_Ret;
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for checking if data is valid.
 * @param   inLen           [IN] Length of input
 *                               - Type: UINT32
 *                               - Range: N/A.
 * @param   pInput          [IN] Pointer of plaintext handshake two
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int l_OnLinePayTaHandle_CheckHandshakeTwo(UINT32 inLen, CHAR* pInput)
{
    UINT16 l_Purpose = 0x0U;
    CHAR* l_DataSection = NULL;
    UINT32 l_dataLen = 0U;
    UINT32 l_RandomLen = 0U;
    CHAR* l_pRandom = NULL;
    int l_Ret = FAIL;
    (void)inLen;
    
    /** 1) Check version of protocol */
    if(PROTOCOL_VERSION != pInput[0])
    {
        TF("PROTOCOL VERSION don't match\n");
        return FAIL;
    }
    
    /** 2) Check version of protocol */
    if(ALGORITHM_VERSION != pInput[1])
    {
        TF("ALGORITHM VERSION don't match\n");
        return FAIL;
    }
    
    /** 3) Get key number of algorithm */
    g_KeyAlgorithm = pInput[4];

    /** 4) Check purpose of package */
    l_Purpose = (pInput[9]) & 0xFFU;
    l_Purpose = (l_Purpose << 8) | pInput[8];
    if(PURPOSE_FOR_HANDSHAKE_TWO != l_Purpose)
    {
        TF("Purpose don't match\n");
        return FAIL;
    }

    /** 5) Get length of data section */
    g_lenOfDataSection = (pInput[13]) & 0xFFU;
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[12];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[11];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[10];
    l_DataSection = &(pInput[14]);

    /** 6) Get data length */
    l_dataLen = (l_DataSection[3]) & 0xFFU;
    l_dataLen = (l_dataLen << 8) | l_DataSection[2];
    l_dataLen = (l_dataLen << 8) | l_DataSection[1];
    l_dataLen = (l_dataLen << 8) | l_DataSection[0];
    TF("Data length is: 0x%04x\n", l_dataLen);

    /** 7) Compare data */
    TF("Input data just like below:\n");
    g_TA_Printf(&(l_DataSection[4]), l_dataLen);
    l_Ret = g_CryptoTaOther_Compare(g_DefHandShakeTwo, &(l_DataSection[4]), l_dataLen);
    if(FAIL == l_Ret)
    {
        return FAIL;
    }

    /** 8) Get second random and saving it */
    l_pRandom = &(l_DataSection[l_dataLen + 4]);
    l_RandomLen = (l_pRandom[3]) & 0xFFU;
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[2];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[1];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[0];
    TF("second random is:%d\n", l_RandomLen);
    g_TA_Printf(&(l_pRandom[4]), l_RandomLen);
    g_CryptoTaHandle_SaveRandomTwo(&(l_pRandom[4]), l_RandomLen);

    return OK;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for packaging third handshaked data.
 * @param   pBuf          [IN] Pointer of third handshakd data
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     l_Ret
 * @retval     return length of valid data
 *
 *
 */
UINT32 l_OnLinePayTaHandle_PackageHandshakeThree(CHAR* pBuf)
{
    UINT32 l_Ret = 0U;
    HandshakeData l_HandData;
    UINT32 l_RandomLen = 16U;

    /** 1) Clean buffer */
    TEE_MemFill(&g_OnLinePayData, 0, sizeof(OnLinePayData));

    /** 2) Assemble data of data section */
    l_HandData.mDataOne = g_DefHandShakeThree;
    l_HandData.mLenOne = sizeof(g_DefHandShakeThree) - 1;

    /** 3) Package plaintext */
    /** 3.1) Package header section */
    g_OnLinePayData.mHeaderSection.mVersion[0] = PROTOCOL_VERSION;  //Version of data
    g_OnLinePayData.mHeaderSection.mVersion[1] = ALGORITHM_VERSION;  // use RSA2048-SHA1-PKCS1 to sign data
    g_OnLinePayData.mHeaderSection.mFrom = DATA_FROM_CLIENT;    // Data from Client
    g_OnLinePayData.mHeaderSection.mTo = DATA_TO_SERVICE;      // Data to service
    g_OnLinePayData.mHeaderSection.mNum = FLAG_HANDSHAKE_KEY;

    /** 3.2) Package data section */
    g_OnLinePayData.mDataSection.mPurpose = PURPOSE_FOR_HANDSHAKE_THREE;
    g_OnLinePayData.mDataSection.mLength = l_HandData.mLenOne + l_RandomLen + 8U;
    g_OnLinePayData.mDataSection.mPdata = (CHAR*)(&l_HandData);

    /** 4) Copy plain data into buffer */
    l_Ret = sizeof(OnLinePayHeaderSection);    //Length of header
    TEE_MemMove(pBuf, &g_OnLinePayData, l_Ret);

    /** 5) Copy purpose data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mPurpose), sizeof(UINT16));
    l_Ret = l_Ret + sizeof(UINT16);

    /** 6) Copy length of section data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mLength), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 7) Copy length of default data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(l_HandData.mLenOne), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 8) Copy default data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), g_DefHandShakeThree, sizeof(g_DefHandShakeThree) -1);
    l_Ret = l_Ret + sizeof(g_DefHandShakeThree) - 1;

    /** 9) Copy length of thrid random into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &l_RandomLen, sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 10) Copy thrid random into buffer */
    g_CryptoTaHandle_GetRandomThree(&(pBuf[l_Ret]), 16);
    l_Ret = l_Ret + 16;

    /** 1) Return length of plain text data */
    return l_Ret;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for packaging pay data.
 * @param   pBuf          [IN] Pointer of paying data
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     l_Ret
 * @retval     return length of valid data
 *
 *
 */
UINT32 l_OnLinePayTaHandle_PackagePayOper(CHAR* pBuf)
{
    UINT32 l_Ret = 0U;
    PayData l_PayData;

    /** 1) Clean buffer */
    TEE_MemFill(&g_OnLinePayData, 0, sizeof(OnLinePayData));

    /** 2) Set default data info into struct of data section */
    l_PayData.mPayData = g_DefPayReq;
    l_PayData.mPayDataLen = sizeof(g_DefPayReq) - 1;

    /** 3) Package plaintext */
    /** 3.1) Package header section */
    g_OnLinePayData.mHeaderSection.mVersion[0] = PROTOCOL_VERSION;  //Version of data
    g_OnLinePayData.mHeaderSection.mVersion[1] = ALGORITHM_VERSION;  // use RSA2048-SHA1-PKCS1 to sign data
    g_OnLinePayData.mHeaderSection.mFrom = DATA_FROM_CLIENT;    // Data from Client
    g_OnLinePayData.mHeaderSection.mTo = DATA_TO_SERVICE;      // Data to service
    g_OnLinePayData.mHeaderSection.mNum = FLAG_DATA_EXCHANGE_KEY;

    /** 3.2) Package data section */
    g_OnLinePayData.mDataSection.mPurpose = PURPOSE_FOR_PAYING_OPERATION;
    g_OnLinePayData.mDataSection.mLength = l_PayData.mPayDataLen + 8U;
    g_OnLinePayData.mDataSection.mPdata = (CHAR*)(&l_PayData);

    /** 4) Copy plain data into buffer */
    l_Ret = sizeof(OnLinePayHeaderSection);    //Length of header + mPurpose + mLength
    TEE_MemMove(pBuf, &g_OnLinePayData, l_Ret);

    /** 5) Put length and data content into bufffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mPurpose), sizeof(UINT16));
    l_Ret = l_Ret + sizeof(UINT16);

    /** 6) Copy length of data section into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mLength), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 7) Copy length of default pay data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), &(l_PayData.mPayDataLen), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);

    /** 8) Copy default pay data into buffer */
    TEE_MemMove(&(pBuf[l_Ret]), g_DefPayReq, sizeof(g_DefPayReq) - 1);
    l_Ret = l_Ret + sizeof(g_DefPayReq) - 1;

    /** 9) Return length of plain text data */
    return l_Ret;
}




/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for checking if data is valid.
 * @param   inLen           [IN] Length of input
 *                               - Type: UINT32
 *                               - Range: N/A.
 * @param   pInput          [IN] Pointer of plaintext handshake two
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int l_OnLinePayTaHandle_CheckPayOver(UINT32 inLen, CHAR* pInput)
{
    UINT16 l_Purpose = 0x0U;
    CHAR* l_DataSection = NULL;
    UINT32 l_dataLen = 0U;
    int l_Ret = FAIL;
    (void)inLen;
    
    /** 1) Check version of protocol */
    if(PROTOCOL_VERSION != pInput[0])
    {
        TF("PROTOCOL VERSION don't match\n");
        return FAIL;
    }

    
    /** 2) Check version of protocol */
    if(ALGORITHM_VERSION != pInput[1])
    {
        TF("ALGORITHM VERSION don't match\n");
        return FAIL;
    }

    
    /** 3) Get key number of algorithm */
    g_KeyAlgorithm = pInput[4];

    /** 4) Check purpose of package */
    l_Purpose = (pInput[9]) & 0xFFU;
    l_Purpose = (l_Purpose << 8) | pInput[8];
    if(PURPOSE_FOR_PAY_OVER!= l_Purpose)
    {
        TF("Purpose don't match\n");
        return FAIL;
    }


    /** 5) Get length of data section */
    g_lenOfDataSection = (pInput[13]) & 0xFFU;
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[12];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[11];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[10];
    l_DataSection = &(pInput[14]);

    /** 6) Get data length */
    l_dataLen = (l_DataSection[3]) & 0xFFU;
    l_dataLen = (l_dataLen << 8) | l_DataSection[2];
    l_dataLen = (l_dataLen << 8) | l_DataSection[1];
    l_dataLen = (l_dataLen << 8) | l_DataSection[0];

    /** 7) Compare data */
    l_Ret = g_CryptoTaOther_Compare(g_PayOperComplete, &(l_DataSection[4]), l_dataLen);
    if(FAIL == l_Ret)
    {
        return FAIL;
    }
    else
    {
        TF("Compare data successful!!!\n");
    }


    return l_Ret;
}






/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for handling command of first handshake from CA.
 * @param   paramTypes      [IN] type of parameter
 *                               - Type: uint32_t
 *                               - Range: N/A.
 * @param   params          [IN] Pointer of parameter
 *                               - Type: TEE_Param
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int g_OnLinePayTaHandle_HandshakeOne(uint32_t paramTypes, TEE_Param params[4])
{
    CHAR* l_pBuf = NULL;    //Point to respond buffer
    UINT32 l_Ret = 0U;
    CHAR* l_pTempBuf = NULL;    //Buffer for plain text
    CHAR* l_pOutBuf = NULL;     //Buffer for cipher text
    UINT32 l_RespondLen = 0U;
    UINT32 l_Index = 0U;

    UNUSED(paramTypes);

    /**1) Get the request length & point of responding buffer */
    l_RespondLen = params[0].memref.size;
    l_RespondLen = 0U;
    l_pBuf = params[0].memref.buffer;

    /** 2) Malloc temp buffer */
    l_pTempBuf = TEE_Malloc(256*3, 0);
    l_pOutBuf = TEE_Malloc(256, 0);

    /** 3) Fill buffer with random */
    g_CryptoTaOther_Random(256U*3U, l_pTempBuf);

    /** 4) Package firstly  plain handshaked data */
    l_Ret = l_OnLinePayTaHandle_PackageHandshakeOne(l_pTempBuf);
    l_Ret = 256U*3U;
    TF("The out put length is\n");
    DHEXDUMP(l_pTempBuf, l_Ret);

    /** 5) Start to encrypt plaintext by using RSA public key */
    while(1)
    {
        if(l_Ret == MAX_RSA_ENC_BLOCK)
        {
            /** 5.1) Encrypt plaintext by RSA2048 */
            g_CryptoTaHandle_Rsa(&(l_pTempBuf[l_Index]), l_Ret, l_pOutBuf, 256U, 
                EM_OP_ENC, PADDING_NO, HANDSHAKE_RSA_KEY_ENC);
            TEE_MemMove(&(l_pBuf[l_RespondLen]), l_pOutBuf, 256U);
            l_RespondLen += 256U;
            break;
        }
        else
        {
            /** 5.1) Encrypt plaintext by RSA2048 */
            g_CryptoTaHandle_Rsa(&(l_pTempBuf[l_Index]), MAX_RSA_ENC_BLOCK, l_pOutBuf, 256U, 
                EM_OP_ENC, PADDING_NO, HANDSHAKE_RSA_KEY_ENC);
            TEE_MemMove(&(l_pBuf[l_RespondLen]), l_pOutBuf, 256U);
            l_Index += MAX_RSA_ENC_BLOCK;
            l_Ret -=MAX_RSA_ENC_BLOCK;
            l_RespondLen += 256U;
        }
        
    }

    /** 6) Free buffer */
    TEE_Free(l_pTempBuf);
    TEE_Free(l_pOutBuf);
    
    return OK;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for handling command of second handshake from CA.
 * @param   paramTypes      [IN] type of parameter
 *                               - Type: uint32_t
 *                               - Range: N/A.
 * @param   params          [IN] Pointer of parameter
 *                               - Type: TEE_Param
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int g_OnLinePayTaHandle_HandshakeTwo(uint32_t paramTypes, TEE_Param params[4])
{
    UINT32 l_RespondLen = 0U;
    CHAR* l_pBuf = NULL;    //Point to respond buffer
    CHAR* l_pTempBuf = NULL;    //Buffer for plain text
    CHAR l_pOutBuf[256] = {0};     //Buffer for cipher text
    UINT32 l_OutLen = 256U;
    int l_Ret = FAIL;
    UNUSED(paramTypes);

    /** 1) Get the request length & point of responding buffer */
    l_RespondLen = params[0].memref.size;
    l_pBuf = params[0].memref.buffer;

    /** 2) Malloc buffer */
    l_pTempBuf = TEE_Malloc(512*3, 0);
    TF("Input length is :%d\n", l_RespondLen);
    g_TA_Printf(l_pBuf, l_RespondLen);

    /** 3) Verify signature */
    g_CryptoTaHandle_Rsa(l_pBuf, (l_RespondLen - 256U), &(l_pBuf[l_RespondLen - 256U]), 
                    256U, EM_OP_VERIFY, PADDING_PKCS1, VER_DATA_FORM_SERVER);

    /** 4) Decrypt data by RSA private */
    g_CryptoTaHandle_Rsa(l_pBuf, (l_RespondLen - 256U), l_pOutBuf, l_OutLen, 
            EM_OP_DEC, PADDING_NO, HANDSHAKE_RSA_KEY_DEC);

    /** 5) Check info & get second random data*/
    TF("Cipher data:\n");
    g_TA_Printf(l_pOutBuf, l_OutLen);
    l_Ret = l_OnLinePayTaHandle_CheckHandshakeTwo(l_OutLen, l_pOutBuf);
    TF("Verify result is: %d\n", l_Ret);

    /** 6) Free buffer */
    TEE_Free(l_pTempBuf);

    /** 7) Return result */
    return l_Ret;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for handling command of third handshake from CA.
 * @param   paramTypes      [IN] type of parameter
 *                               - Type: uint32_t
 *                               - Range: N/A.
 * @param   params          [IN] Pointer of parameter
 *                               - Type: TEE_Param
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int g_OnLinePayTaHandle_HandshakeThree(uint32_t paramTypes, TEE_Param params[4])
{
    CHAR* l_pBuf = NULL;    //Point to respond buffer
    CHAR l_pOutBuf[256] = {0};     //Buffer for cipher text
    CHAR l_pTempBuf[512] = {0};
    UINT32 l_Ret = 0U;
    UNUSED(paramTypes);

    /** 1) Get the request length & point of responding buffer */
    l_pBuf = params[0].memref.buffer;

    /** 2) Fill buffer with random */
    g_CryptoTaOther_Random(512U, l_pTempBuf);

    /** 3) Package plaintext of third handshaking data */
    l_Ret = l_OnLinePayTaHandle_PackageHandshakeThree(l_pTempBuf);
    TF("Plain text data: %d\n", l_Ret);
    g_TA_Printf(l_pTempBuf, l_Ret);

    /** 4) Encrypt plaintext by RSA2048 */
    g_CryptoTaHandle_Rsa(l_pTempBuf, MAX_RSA_ENC_BLOCK, l_pOutBuf, 256U, 
        EM_OP_ENC, PADDING_NO, HANDSHAKE_RSA_KEY_ENC);
    TF("Cipher data\n");
    g_TA_Printf(l_pOutBuf, 256);

    /** 5) Copy encrypted data into out buf */
    TEE_MemMove(l_pBuf, l_pOutBuf, 256U);

    /** 6) Copy data to respond */
    TEE_MemFill(l_pTempBuf, 0, 256);
    g_CryptoTaHandle_Rsa(l_pOutBuf, 256U, l_pTempBuf, 256U, 
        EM_OP_SIGN, PADDING_PKCS1, SIGN_DATA_TO_SERVER);
    TF("Signature data\n");
        g_TA_Printf(l_pTempBuf, 256);

    /** 7) Copy signature data into buf */
    TEE_MemMove(&(l_pBuf[256U]), l_pTempBuf, 256U);
        TF("Return data data\n");
        g_TA_Printf(l_pBuf, 512);

    /** 8) Set AES key&IV of data exchanging between client and server */
    g_CryptoTaHandle_SetAesKey();

    /** 9) Return result */
    return OK;
}




/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for handling command of paying operation from CA.
 * @param   paramTypes      [IN] type of parameter
 *                               - Type: uint32_t
 *                               - Range: N/A.
 * @param   params          [IN] Pointer of parameter
 *                               - Type: TEE_Param
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int g_OnLinePayTaHandle_pay(uint32_t paramTypes, TEE_Param params[4])
{
    CHAR* l_pBuf = NULL;    //Point to respond buffer
    UINT32 l_Ret = 0U;
    CHAR* l_pTempBuf = NULL;    //Buffer for plain text
    CHAR* l_pOutBuf = NULL;     //Buffer for cipher text
    
    UNUSED(paramTypes);

    /**1) Get the request length & point of responding buffer */
    l_pBuf = params[0].memref.buffer;

    /** 2) Malloc buffer for paying operation */
    l_pTempBuf = TEE_Malloc(512, 0);
    l_pOutBuf = TEE_Malloc(256, 0);

    /** 3) Fill buffer with random */
    g_CryptoTaOther_Random(512, l_pTempBuf);

    /** 4) Package plaintext of paying data */
    l_Ret = l_OnLinePayTaHandle_PackagePayOper(l_pTempBuf);
    TF("The plain text length is : %d\n", l_Ret);

    /** 5) Encrypt plaintext by AES128 */
    g_CryptoTaHandle_Aes(l_pTempBuf, 256U, l_pOutBuf, EN_OP_AES_ENCRYPT, EN_MODE_CBC);

    /** 6) Copy encrypted data into out buf */
    TEE_MemFill(l_pTempBuf, 0, 512);
    TEE_MemMove(l_pTempBuf, l_pOutBuf, 256);
    TEE_MemFill(l_pOutBuf, 0, 256);

    /** 7) Sign cipher data */
    g_CryptoTaHandle_Rsa(l_pTempBuf, 256U, l_pOutBuf, 256U, 
        EM_OP_SIGN, PADDING_PKCS1, SIGN_DATA_TO_SERVER);

    /** 8) Copy signature data and cipher data into buf */
    TEE_MemMove(l_pBuf, l_pTempBuf, 256);
    TEE_MemMove(&(l_pBuf[256]), l_pOutBuf, 256);
    
    /** 9) Free buffer */
    TEE_Free(l_pTempBuf);
    TEE_Free(l_pOutBuf);
    
    return OK;
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for handling command of paying over from CA.
 * @param   paramTypes      [IN] type of parameter
 *                               - Type: uint32_t
 *                               - Range: N/A.
 * @param   params          [IN] Pointer of parameter
 *                               - Type: TEE_Param
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     FAIL/OK
 *
 *
 */
int g_OnLinePayTaHandle_payOver(uint32_t paramTypes, TEE_Param params[4])
{
    UINT32 l_RespondLen = 0U;
    CHAR* l_pBuf = NULL;    //Point to respond buffer
    CHAR* l_pTempBuf = NULL;    //Buffer for plain text
    CHAR* l_pOutBuf = NULL;     //Buffer for cipher text
    
    UNUSED(paramTypes);

    /** 1) Get the request length & point of responding buffer */
    l_RespondLen = params[0].memref.size;
    l_pBuf = params[0].memref.buffer;
    l_pTempBuf = TEE_Malloc(512*3, 0);
    l_pOutBuf = TEE_Malloc(512*3, 0);
    TF("Input data from CA:\n");
    g_TA_Printf(l_pBuf, l_RespondLen);

    /** 2) Verify signature */
    g_CryptoTaHandle_Rsa(l_pBuf, (l_RespondLen - 256U), &(l_pBuf[l_RespondLen - 256U]), 
                    256U, EM_OP_VERIFY, PADDING_PKCS1, VER_DATA_FORM_SERVER);

    /** 3) Decrypt data */
    TF("Cipher data:\n");
    g_TA_Printf(l_pBuf, (l_RespondLen - 256U));
    g_CryptoTaHandle_Aes(l_pBuf, (l_RespondLen - 256U), l_pTempBuf, 
            EN_OP_AES_DECRYPT, EN_MODE_CBC);

    /** 4) Check info & get second random data*/
       TF("Plain data:\n");
    g_TA_Printf(l_pTempBuf, 256U);
    l_OnLinePayTaHandle_CheckPayOver((l_RespondLen - 256U), l_pTempBuf);

    /** 7) Free buffer */
    TEE_Free(l_pTempBuf);
    TEE_Free(l_pOutBuf);

    return OK;
}


/**
 * @}
 */
