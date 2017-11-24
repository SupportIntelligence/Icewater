
rule k2319_1299a999c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1299a999c6220b32"
     cluster="k2319.1299a999c6220b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script phishing daea"
     md5_hashes="['4fcb0c89de2ba838b6f9b10159b3d9b9','5246f918392eecdff43e2a6813cf96a7','909074d5cbaf383ce3606cc667efa4a8']"

   strings:
      $hex_string = { 72697a7a6f223e0a093c703e427574746572666c79204d757369632073726c202d20766961205a7572657474692c2034372f42203230313235204d494c414e4f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
