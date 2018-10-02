
rule k2319_1a1238e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1238e9c8800b12"
     cluster="k2319.1a1238e9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['81554a8ae405d28910345261897245573fb3858c','866edb3575bf7d710857624020a6f68be73ef5db','1313681c389e07c54bc4c5ae936c5214f29223cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1238e9c8800b12"

   strings:
      $hex_string = { 572c552c47297b696628595b475d213d3d756e646566696e6564297b72657475726e20595b475d3b7d766172206f3d282838372e333045312c312e3239354533 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
