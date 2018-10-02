
rule k2319_293686b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.293686b9c2200b32"
     cluster="k2319.293686b9c2200b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['2cd3faf7fcd8d482c4c8df7b7a77a9c0a11fe622','215b003d5706f1162bbb75f5e22693cc24db3a31','5c297b1205b45d124a87737332a7ca8fdccedf27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.293686b9c2200b32"

   strings:
      $hex_string = { 28382e3945312c34302e33304531292929627265616b7d3b766172206a356237613d7b27613642273a226368222c2778386f273a66756e6374696f6e28712c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
