
rule m2319_16b21ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.16b21ec9c4000932"
     cluster="m2319.16b21ec9c4000932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['b20908916daca35fafc00890dad2655a0c63be48','bb999c5522d13ff94ca4fb142713ff985e8c85bf','7ee1d4e76cd63964205bc14caa789c4871c5c609']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.16b21ec9c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
