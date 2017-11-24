
rule m2319_3b1b3ec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b1b3ec1c8000912"
     cluster="m2319.3b1b3ec1c8000912"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['04a7293dc55a10fdb523b54eb8a56572','39646e4d56630704cdec41f68d372d6e','d41dc2ff5f71ddc2c671e47e99dbf48e']"

   strings:
      $hex_string = { 312f762d6373732f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
