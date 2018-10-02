
rule m2319_1ec957a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ec957a9ca000b12"
     cluster="m2319.1ec957a9ca000b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['33a2055db12d924529b4f0d7a53fc7147714b6d8','9eaa699b3a15c327b6a2da16b2d95a7430cec05a','8139beda97a6f4c1f890403764d77a1208b47839']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ec957a9ca000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
