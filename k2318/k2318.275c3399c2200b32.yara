
rule k2318_275c3399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.275c3399c2200b32"
     cluster="k2318.275c3399c2200b32"
     cluster_size="12926"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['0e3fc67e8c8db0921d9cca5f574534c987df0303','bae846ca455d7a534d103df88d6be8ffd3befab6','b4036c296a6c9d4c9f4669568caf1c7779721058']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.275c3399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
