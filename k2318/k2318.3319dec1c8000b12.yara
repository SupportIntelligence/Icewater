
rule k2318_3319dec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3319dec1c8000b12"
     cluster="k2318.3319dec1c8000b12"
     cluster_size="334"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['3b9c43f55e0973c2eae709d1bdad274bad42f9f0','040da5334a79a7bf9aeb3fb501f805043a6c0f2a','887c0f3a5a7e74e537e2b5b93e0304468342c418']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3319dec1c8000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
