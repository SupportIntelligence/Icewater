
rule m2319_14ba3ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14ba3ac1c8000932"
     cluster="m2319.14ba3ac1c8000932"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['4fa4038043cb54718ab28e83cf41d1a93f698f3c','f4d31cad5d89a23158f8dcd66d038e6af6c870c2','95c2a5899904c808a2a7ea3f321039bbacc19544']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14ba3ac1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
