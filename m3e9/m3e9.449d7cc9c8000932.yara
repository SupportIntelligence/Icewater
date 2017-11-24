
rule m3e9_449d7cc9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.449d7cc9c8000932"
     cluster="m3e9.449d7cc9c8000932"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbcrypt changeup"
     md5_hashes="['a328403a960f92b6bbc02bea2df95331','bec5864243d5803f8c6298114c4105c8','e34751ba7bb94e8874328e1246ec29e9']"

   strings:
      $hex_string = { 317d1e023b3e543f72a4a9c696303b565b5b5c02595c6698efecedf84b3200000000000000000000000084f5fffafe08ffcbffe592731f4e86838ea1a9cf8e24 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
