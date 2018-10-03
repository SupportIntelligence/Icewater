
rule m2319_36b6b4a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.36b6b4a9c8800b12"
     cluster="m2319.36b6b4a9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['3a48f222fd6db5e3416056d452a8880fefff7bc1','0f4dac4ad54e40a424d539a9fa9f3115a0446f74','cbb414b1e17005bdde2713af0352e345833bd1cc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.36b6b4a9c8800b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
