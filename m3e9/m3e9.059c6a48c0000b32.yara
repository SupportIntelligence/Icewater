
rule m3e9_059c6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.059c6a48c0000b32"
     cluster="m3e9.059c6a48c0000b32"
     cluster_size="201"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['00960f50d08e3704d13a75bd406195ec','02f5e93a3ab8fbb5b3618cf39b5c7a6f','11e9a8b08b8263a0fb736ce774b8c121']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba160e700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff15d010 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
