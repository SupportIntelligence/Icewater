
rule o26d5_422dea49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.422dea49c0000912"
     cluster="o26d5.422dea49c0000912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious gifq"
     md5_hashes="['70d9b9bad565c83455a42d1882031a1f081f7c54','beead9cca9d87f59bc24a0cf133a66c66d2efbaf','4d0ca9c01ed8e524a704acb85d5715539fcbb80e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.422dea49c0000912"

   strings:
      $hex_string = { 032905461bb26c8ac1b1019450a8a44110b90d549e4df18300cf0bd0454e610c51ad4918d7f04267f49a8efb04718de1ce06322fab20e2eff23560dc9823692c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
