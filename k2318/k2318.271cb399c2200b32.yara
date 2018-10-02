
rule k2318_271cb399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.271cb399c2200b32"
     cluster="k2318.271cb399c2200b32"
     cluster_size="2175"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['10248f20342cb32f0b6e85cc72e9e86dc87ce4e6','e36830b0f6b0feffb8393931fd3b8a2676b5fbce','c66bff5eaec3263a0c157f3091f6e5ef2551f484']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.271cb399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
