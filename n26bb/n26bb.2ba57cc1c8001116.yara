
rule n26bb_2ba57cc1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2ba57cc1c8001116"
     cluster="n26bb.2ba57cc1c8001116"
     cluster_size="212"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ransom gandcrab chapak"
     md5_hashes="['e1781c5cdaa383575f4c1a10323ba66877632b11','d96750e0222c9500549786eda4d7701da34b0b8f','82e0903efcac674a45d9b0381446375b55ed83fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2ba57cc1c8001116"

   strings:
      $hex_string = { c65e5dc3578bfe2bf90fb7016689040f8d49026685c074034a75ee33c05f85d275df668906e8cd84ffff6a22ebc9558bec51a130ba420033c58945fc8b4d1c53 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
