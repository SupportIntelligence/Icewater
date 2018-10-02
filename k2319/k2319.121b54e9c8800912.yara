
rule k2319_121b54e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.121b54e9c8800912"
     cluster="k2319.121b54e9c8800912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['09e2a0e557161f11019a2886dcf6fca37c7aaf61','fe5a7a900a586b73aae73a06c1f8bc67557be385','1a61b336a87936ffef4ee468074440737c5cef02']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.121b54e9c8800912"

   strings:
      $hex_string = { 293a28332e363445322c3078313433292929627265616b7d3b7661722074356c3d7b27563270273a22696e7374616c6c5f74696d65222c275a30273a66756e63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
