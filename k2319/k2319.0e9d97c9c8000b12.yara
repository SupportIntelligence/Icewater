
rule k2319_0e9d97c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.0e9d97c9c8000b12"
     cluster="k2319.0e9d97c9c8000b12"
     cluster_size="158"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['729511be819bb64a1079222d1397869d55bce81d','f76e337409212ff4c2ab6d7ca9c2daa15bfa0457','f080fe08d4f762ca0bb824bc0b68059c6ad83094']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.0e9d97c9c8000b12"

   strings:
      $hex_string = { 75704f7665726c617927292e686964652829223e454e5445523c2f613e3c62723e3c62723e0a3c61207374796c653d22666f6e742d73697a653a20313270783b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
