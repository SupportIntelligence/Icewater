
rule o422_51e1e482c0000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.51e1e482c0000132"
     cluster="o422.51e1e482c0000132"
     cluster_size="24775"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitminer malicious risktool"
     md5_hashes="['55fd9c7c5a29ed67e4815213af6d812a4759f16c','88b24703e26f7904fb2dae3105167a644dcdc334','605004a174e36a7c2c26ccb6b355224858db96f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.51e1e482c0000132"

   strings:
      $hex_string = { 75042a982bbdf8d5f2d23962e720c6b4f4da261ba1415c46c3c45fe061b11e293e91cd9bb6c5366a84e3101a6eba0d348df7c01215e4bc40275ecbd9eaa4dd80 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
