
rule m3e9_3b914a5eda9f1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b914a5eda9f1916"
     cluster="m3e9.3b914a5eda9f1916"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['1f617b17e6dfc6712820b62ae8b9816b','5a4b062b54db5ca2f7d10501c12a2f4d','c5db9af8a8842ef980383c50c5c2d64a']"

   strings:
      $hex_string = { 8d78915e20a8c6ec30976e3d8bd3aa42d45ca59026afb3b281b5c82a2ec31ac448a1093b24bed472f67f6135330addb17ca47dbfc16ba286fad52ba9117657e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
