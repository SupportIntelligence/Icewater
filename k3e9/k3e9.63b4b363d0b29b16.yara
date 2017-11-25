
rule k3e9_63b4b363d0b29b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d0b29b16"
     cluster="k3e9.63b4b363d0b29b16"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['218fb7f2083effc33220d6ce7ca12051','314c86cd3f4bece3238e493467f18f22','ec1650f2d8fdcbf29ef751d1cb92e4f3']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba1a08700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff158410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
