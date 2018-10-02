
rule k2318_5294b94dc2220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294b94dc2220912"
     cluster="k2318.5294b94dc2220912"
     cluster_size="283"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['c3fa6764a5fa855d6418f745d1b972163fe3a795','cecec9d5f38a5dea7621f94f5711cb74ea81f480','61a5cb6157f9290211897e88c535f70ebcbab6d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294b94dc2220912"

   strings:
      $hex_string = { 683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
