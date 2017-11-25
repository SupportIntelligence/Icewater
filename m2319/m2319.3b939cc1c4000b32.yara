
rule m2319_3b939cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b939cc1c4000b32"
     cluster="m2319.3b939cc1c4000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['1ce62d9d1a9b9e993ceece150c9267a3','54cd4511909b025111492d75df7b9f12','e42d9ff028a523396a4d68402484d0f6']"

   strings:
      $hex_string = { 456c656d656e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f7363726970743e0a3c2f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
