
rule m26bb_2676e716af394b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2676e716af394b16"
     cluster="m26bb.2676e716af394b16"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adposhel generickd heuristic"
     md5_hashes="['0f2b8ffe1991f6e3c410182fd46a0e9e03370986','68e89a8a4074453125aeefa4f5ba3ea74c795c02','e2033d2f0a20f4e530d53b6d1304bbddb7ebad67']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2676e716af394b16"

   strings:
      $hex_string = { 1878e98fcd5eb35939860e09f6a4ba2d158a57877721dce708d02c883e22e48e0a7140ea9847fa6cb8453adb348b94ab80f43cbe61e591f75273b699cedf970c }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
