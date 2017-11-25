
rule m3e9_611e9689c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e9689c6620b12"
     cluster="m3e9.611e9689c6620b12"
     cluster_size="137"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['0106f09f723204d0bac23ed37c591b97','02bfb9321bf22eea3169044189929aaa','34b1e5051ad0ad3048cd3ce7f31d5114']"

   strings:
      $hex_string = { 0cfa4d6a8edacf4a10bb512b929bd30b147c55ec965cd7cc183d59ad9a1ddb8d1cfe5d6e9ededf4e20bf612fa29fe30f248065f0a660e7d0284169b1aa21eb91 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
