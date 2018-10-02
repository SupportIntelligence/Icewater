
rule m2319_3a90ea48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3a90ea48c0000912"
     cluster="m2319.3a90ea48c0000912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script classic"
     md5_hashes="['65a324f1cb72477b2bb8ceddec7fb898e7664c05','3413518a41b2eca2388b94acd590760d7d5a0ac7','a96e515483ea8bbdc6454537f16c64f6d1a2bfef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3a90ea48c0000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
