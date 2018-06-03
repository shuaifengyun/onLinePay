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
 *               cryptoRsa.c
 *
 * Filename      : cryptoRsa.c
 * Programmer(s) : system BSP
 * Filename      : cryptoRsa.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:01:51 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_RSA_C_

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
#include "cryptoSha.h"





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





/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Encrypt(CHAR* pubKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PubFp = NULL;
    RSA* l_RsaPubText = NULL;
    int l_Ret = -1;


    /**1) Open public key file */
    l_PubFp = fopen(pubKeyFile, "r");
    if(NULL == l_PubFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPubText = PEM_read_RSA_PUBKEY(l_PubFp, NULL, NULL, NULL);
    if(NULL == l_RsaPubText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPubText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPubText->e));
    printf("Input Data Length is: %d\n", inLen);
    printf("Input data just like follow:\n");
    printf("%s\n", inputBuf);
    printf("\n\n");

    /**4) RSA Encrypt Input data */
    l_Ret = RSA_public_encrypt(inLen, inputBuf, outputBuf, l_RsaPubText, padType);
    if(-1 == l_Ret)
    {
        printf("ERROR: encrypt input data faile!\n");
        return -1;
    }

    return l_Ret;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Decrypt(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PriFp = NULL;
    RSA* l_RsaPriText = NULL;
    int l_Ret = -1;
    UINT32 l_RetNum = 0U;
    UINT32 l_Index = 0U;
    CHAR l_Buf[256] = {0};
    


    /**1) Open public key file */
    l_PriFp = fopen(priKeyFile, "r");
    if(NULL == l_PriFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPriText = PEM_read_RSAPrivateKey(l_PriFp, NULL, NULL, NULL);
    if(NULL == l_RsaPriText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPriText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPriText->d));

	  while(1)
	  {
	  		if(inLen == 256U)
	  		{
		        /**4) RSA Encrypt Input data */
		        memset(l_Buf, 0, 256);
		        l_Ret = RSA_private_decrypt(256, &(inputBuf[l_RetNum]), l_Buf, l_RsaPriText, padType);
		        if(-1 == l_Ret)
		        {
		            printf("ERROR: encrypt input data faile!\n");
		            return -1;
		        }
		        memcpy(&(outputBuf[l_Index]), l_Buf, l_Ret);
		        printf("RSA dec-pkcs1 output just like follow %d:\n", l_Index);
            g_Debug_Printf(l_Buf, 256);
		        break;
		    }
		    else
		    {
		    		memset(l_Buf, 0, 256);
		    		l_Ret = RSA_private_decrypt(256, &(inputBuf[l_RetNum]), l_Buf, l_RsaPriText, padType);
		        if(-1 == l_Ret)
		        {
		            printf("ERROR: encrypt input data faile!\n");
		            return -1;
		        }
		        else
		        {
		        		memcpy(&(outputBuf[l_Index]), l_Buf, l_Ret);
		        		printf("RSA dec-pkcs1 output just like follow %d:\n", l_Index);
            		g_Debug_Printf(l_Buf, 256);
		        	  inLen = inLen - 256U;
		        	  l_RetNum = l_RetNum + 256;
		        	  l_Index = l_Index + l_Ret;
		        	  

		        }
		    }
    }

    return l_Ret;
    
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Sign(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PriFp = NULL;
    RSA* l_RsaPriText = NULL;
    int l_Ret = -1;


    /**1) Open public key file */
    l_PriFp = fopen(priKeyFile, "r");
    if(NULL == l_PriFp)
    {
        printf("ERROR: Open private key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPriText = PEM_read_RSAPrivateKey(l_PriFp, NULL, NULL, NULL);
    if(NULL == l_RsaPriText)
    {
        ERR_print_errors_fp(stdout);
        printf("ERROR: read private key from file faile!\n");
        return -1;
    }
    else
    {
        printf("\nPrivate key:\n");
        printf("n=%s\n", BN_bn2hex(l_RsaPriText->n));
        printf("d=%s\n\n", BN_bn2hex(l_RsaPriText->d));
    }
    printf("Input Data Length is: %d\n", inLen);
    printf("Input data just like follow:\n");
    printf("%s\n", inputBuf);

    
    /**4) RSA Encrypt Input data */
    l_Ret = RSA_private_encrypt(inLen, inputBuf, outputBuf, l_RsaPriText, padType);
    printf("%d\n", l_Ret);
 
    if(-1 == l_Ret)
    {
        printf("ERROR: Signature input data faile!\n");
        return -1;
    }

    return l_Ret;
}



int l_CryptoRsa_Compare(CHAR* bufOne, CHAR* bufTwo, UINT32 len)
{
    UINT32 l_Index = 0U;

    for(l_Index = 0U; l_Index < len; l_Index++)
    {
        if(bufOne[l_Index] != bufTwo[l_Index])
            return -1;
    }

    return 0;
}





/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Verify(CHAR* pubKeyFile, CHAR* RawBuf, UINT32 rawLen, CHAR* signBuf, int padType)
{
    FILE* l_PubFp = NULL;
    RSA* l_RsaPubText = NULL;
    CHAR l_Tmp[256] = {0};
    CHAR l_hash[20] = {0};
    int l_Ret = -1;


    /**1) Open public key file */
    l_PubFp = fopen(pubKeyFile, "r");
    if(NULL == l_PubFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPubText = PEM_read_RSA_PUBKEY(l_PubFp, NULL, NULL, NULL);
    if(NULL == l_RsaPubText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPubText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPubText->e));

    /**4) RSA Encrypt Input data */
    l_Ret = RSA_public_decrypt(RSA_size(l_RsaPubText), signBuf, l_Tmp, l_RsaPubText, padType);
    printf("The return value is %d\n", l_Ret);
    g_Debug_Printf(l_Tmp, 256);

    //l_Ret = RSA_verify(NID_sha1, RawBuf, 20, signBuf, 256, l_RsaPubText);
    //printf("The return value is: %d\n", l_Ret);
    //if(-1 == l_Ret)
    //{
    //    printf("ERROR: Call openssl verify function fail\n");
   //     return -1;
  //  }
    
    /**5) Compare the result */
    g_CryptoSha_shaOper(EN_OP_SHA1, RawBuf, rawLen, l_hash);
    TF("Hash of input:\n");
    g_Debug_Printf(l_hash, 20);

    TF("Dec hash :\n");
    g_Debug_Printf(&(l_Tmp[15]), 20);
    l_Ret = memcmp(l_hash, &(l_Tmp[15]), 20);
    if(0 != l_Ret)
    {
        printf("Verify signature information faile!!!\n");
        return -1;
    }
    else
    {
        printf("Verify signature information ok!!!\n");
    }

    return l_Ret;
}





















/**
 * @}
 */
