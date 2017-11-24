
rule m3e9_316338779d3b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338779d3b1112"
     cluster="m3e9.316338779d3b1112"
     cluster_size="135"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['00651ece65930b2efaa6227a5ff1d030','02156a077f8f3517ae6760687a7fa024','1ee75d8fc67444093447c3324d2cd421']"

   strings:
      $hex_string = { 8d78915e20a8c6ec30976e3d8bd3aa42d45ca59026afb3b281b5c82a2ec31ac448a1093b24bed472f67f6135330addb17ca47dbfc16ba286fad52ba9117657e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
