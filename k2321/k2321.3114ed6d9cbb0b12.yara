
rule k2321_3114ed6d9cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.3114ed6d9cbb0b12"
     cluster="k2321.3114ed6d9cbb0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['0528f11a662bd5a590ab557a80b30426','d69ec86f0549b1624df4ca4d1c1329e9','e5d52d1a71a50c1d8228f9e51f07fd57']"

   strings:
      $hex_string = { 3b23929d1bce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
