
rule n2319_13bb33a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13bb33a9c8800932"
     cluster="n2319.13bb33a9c8800932"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['b46459dd624d69e77f7f6d35567b997335fd225a','7122e92300e5a9f4f49716c7996f952653033594','53ffacae0f433c42350921dec330cbd0b88dc2e7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13bb33a9c8800932"

   strings:
      $hex_string = { 74262621772e6973456d7074794f626a6563742874297d7d3b766172204a3d6e657720512c4b3d6e657720512c5a3d2f5e283f3a5c7b5b5c775c575d2a5c7d7c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
