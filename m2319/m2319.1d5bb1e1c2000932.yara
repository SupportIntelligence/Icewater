
rule m2319_1d5bb1e1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d5bb1e1c2000932"
     cluster="m2319.1d5bb1e1c2000932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['396325b8ebe4cf07e103abf477e8c623c2d626ea','fe40db8139e0b326eb1e3c3428977ba3351b64cb','d5905f74b9342dffa7f5a8bdd16dc4ce84a7faeb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d5bb1e1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
