
rule k2321_19189fa9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19189fa9ca000912"
     cluster="k2321.19189fa9ca000912"
     cluster_size="34"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['1397ba78fd83ba785f8b806b71d77ac3','25d082dfac164cf754ec06c5329e4700','7ca72f6488363e0d93e3374e4b559de4']"

   strings:
      $hex_string = { a5c229728a00a7b71f2fe1a8d8767c24d22b28323c56f9ccb60acdb4be66afdbba9e788d104c0fc571bd0cb391a126f3f07cd7e615c6ee99780e93424555ff22 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
