
rule m2319_12b39ec1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.12b39ec1c4000932"
     cluster="m2319.12b39ec1c4000932"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['1e61ca92b74e8909d7ea029e429d5ac5b0ef7883','20e08cf7d9aad15c092600fb4b0bd8a096ecb860','9dc3511f475c336ca046d26d3c8419b18eb7b950']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.12b39ec1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
