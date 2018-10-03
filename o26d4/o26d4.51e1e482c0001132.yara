
rule o26d4_51e1e482c0001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.51e1e482c0001132"
     cluster="o26d4.51e1e482c0001132"
     cluster_size="4149"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy bitminer bitcoinminer"
     md5_hashes="['0cbda005d8bce450e34cf6782a89e879f8d6bc2c','94e632af4a9980b753108b99f88fc2f5069ce0f8','0f772cac197fa6be7d1bac458cfc3cb49e236d6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.51e1e482c0001132"

   strings:
      $hex_string = { 75042a982bbdf8d5f2d23962e720c6b4f4da261ba1415c46c3c45fe061b11e293e91cd9bb6c5366a84e3101a6eba0d348df7c01215e4bc40275ecbd9eaa4dd80 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
