
rule m2319_14ba1ec1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14ba1ec1c8000932"
     cluster="m2319.14ba1ec1c8000932"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['8dad6267bc01e76a3e6a6e6b6727760cba812a38','18d51968f434a1ba414ab24d9eeb5db4e205c42c','9e4727c51717a3faf2b139fb61614961d57b86f7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14ba1ec1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
