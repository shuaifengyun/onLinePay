    server_tools主要包含了在线支付系统服务器端使用的简单工具，可用于本示例中TA数据包的验证
主要包含如下内容：
1. 第一次握手请求数据包的验证、解密、解析
2. 第二次握手请求的组包、加密、签名
3. 第三次握手请求数据包的验证、解密、验证
4. 支付请求数据包的验证、解密、解析
5. 支付请求反馈主举报的组包、加密、签名

工具的编译和清除：
   进入到server_tools目录分别使用如下指令进行编译和清除
          编译该工具：   make
        清除编译结果：   make clean

工具的使用（该工具将相关的数据已经hardcode在main.c文件中，读者可根据实际的数据包内容进行替换）：

1. 解析第一次握手请求的命令：
      ./serverTool hsone key/handshake_from_service.pem 

2. 组包第二次握手请求的命令：
      ./serverTool hstwo key/device_rsaPublic.pem key/handshake_from_service.pem
      
3. 解析第三次握手请求的命令：
      ./serverTool hsthree key/device_rsaPublic.pem key/handshake_from_service.pem

4. 解析支付请求的命令（解密使用的AES秘钥已经hardcode在代码中，应该使用第三次握手中计算出的AES秘钥进行替换）：
      ./serverTool payreq key/device_rsaPublic.pem

5. 组包支付请求反馈数据包的命令：
      ./serverTool payover key/handshake_from_service.pem
      
Note： 本工具只是做简单的验证，如果读者需要修改数据，和使用真的随机数替换握手的信息，可以通过修改代码来实现
