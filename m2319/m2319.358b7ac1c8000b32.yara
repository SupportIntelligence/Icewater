
rule m2319_358b7ac1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.358b7ac1c8000b32"
     cluster="m2319.358b7ac1c8000b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['196844a23f7e3fe5db4e5fc67ff623fd','22d603a871c781e02d0a11d94674095c','fe210eaa400f3ea8ec2d6eace4c590e7']"

   strings:
      $hex_string = { 43454d454e555f44524f505f414c4c4f575f5749445448333634203d2066616c73653b0a0d66756e6374696f6e20737461727447616c6c6572792829207b0a09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
