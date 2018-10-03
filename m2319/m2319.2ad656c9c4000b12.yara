
rule m2319_2ad656c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2ad656c9c4000b12"
     cluster="m2319.2ad656c9c4000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['105109c0840153c8ef256dac4791451642d7049f','e29c0d527f1923174ab52de315d6372c35b93ad1','686c74bad7b8808f7190a3b7149c82d3ef89c4b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2ad656c9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
