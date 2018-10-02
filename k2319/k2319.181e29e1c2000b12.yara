
rule k2319_181e29e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181e29e1c2000b12"
     cluster="k2319.181e29e1c2000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7c7741dbbfb894ca3663a2a00ec4aa7a62676a71','760ede501a30747988f78c4faae7ae855342dae3','0c67f5a7b08ae36bf2bb4bd50fef0e3190435b10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181e29e1c2000b12"

   strings:
      $hex_string = { 352e383245322c313139293a2837392c3078313234292929627265616b7d3b766172206a3762383d7b27643274273a226365222c277138273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
