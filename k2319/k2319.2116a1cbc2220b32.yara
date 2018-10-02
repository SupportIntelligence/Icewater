
rule k2319_2116a1cbc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2116a1cbc2220b32"
     cluster="k2319.2116a1cbc2220b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['4f8166e8343b38fd3de08b00bf15d511ffd380c5','c2d8a1a4e59afd7c3484980deb42d32940e9be71','52fa889c0cd0a17e5f4ba61a1275a0cc9057d8e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2116a1cbc2220b32"

   strings:
      $hex_string = { 2839342c3937292929627265616b7d3b7661722070356730353d7b275a3335273a66756e6374696f6e28432c44297b72657475726e20433e443b7d2c274b3253 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
