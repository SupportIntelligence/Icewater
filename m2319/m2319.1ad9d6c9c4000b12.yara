
rule m2319_1ad9d6c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ad9d6c9c4000b12"
     cluster="m2319.1ad9d6c9c4000b12"
     cluster_size="571"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['c6a00d363f3f4c617e34d7e919ef61a544b899f7','b726160a5bb7c49f5a9b0ad83d2c1af2dce48d0a','825e5ba2ad139e93a3f6346609c374e0ffa8fad9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ad9d6c9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
