
rule m3f7_52b92007002b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52b92007002b4993"
     cluster="m3f7.52b92007002b4993"
     cluster_size="7"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0a2d5d4b6f8da086fa042a2dd8fccff7','158d4a0fa6fa55628597813d9ca1af66','bef6e9a16e2ea4677ccd1de18ec37fc5']"

   strings:
      $hex_string = { a782205b62ef8d3f213fe7dcecc03f32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
