# onLinePay
demo of on line pay

    本文主要介绍onLinePay的示例TA和CA的使用，主要是CA中所支持的命令说明；
    本示例中的CA实现了如下功能：
1. 第一次握手请求的组包、加密
2. 第二次握手数据包的解密、验证、解析
3. 第三次握手请求的组包、加密、签名
4. 支付请求数据包的组包、加密、签名
5. 支付请求反馈数据包的解密、验证、解密

    上述指令主要是在REE侧执行onLinePay的相关指令来实现的，执行的命令和说明如下：
1. 产生第一次握手请求的数据包：
  onLinePay hsone

2. 解析第二次握手数据包：
  onLinePay hstwo

3. 产生第三次握手请求的数据包：
  onLinePay hsthree

4. 产生支付请求数据包：
  onLinePay payreq
  
5. 解析支付请求反馈数据包：
  onLinePay payover

NOTE:
    握手请求中的随机数都hardcode在代码中，读者可将对应的数据替换成生成随机数接口就可
