
rule m2377_3d5a7ac1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3d5a7ac1c8000b12"
     cluster="m2377.3d5a7ac1c8000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['0039859d8c8c1e69045b73a0a2e2c19b','7941fb8be6991e8bf7b382e7b8c323b7','e2f151f99cde37e125f9ad855109e02c']"

   strings:
      $hex_string = { 233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563686f732072657365727661646f732e3c6272202f3e3c2f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
