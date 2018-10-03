
rule k2318_37125aadc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37125aadc6220b12"
     cluster="k2318.37125aadc6220b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['d4b2a1b2bb85c55c578adfdff94da3e7b59df5f2','d036f9389fe97ba493e8e50cefa523cb97402d3c','ee466be34c7368f2657be8f6b01c027a507c555a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37125aadc6220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
