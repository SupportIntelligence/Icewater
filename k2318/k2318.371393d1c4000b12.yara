
rule k2318_371393d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371393d1c4000b12"
     cluster="k2318.371393d1c4000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['b8eb484e7c4f1fe5fc3117e588ed6867c21296cd','2a80a6f16ef3530c7143d87d27dc70fe95fd5f5d','fdf3ddfb7fbbeda276318bdecfd0c2360f6600ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371393d1c4000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
