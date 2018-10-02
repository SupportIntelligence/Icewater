
rule m2319_150ab5e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.150ab5e9c8800932"
     cluster="m2319.150ab5e9c8800932"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['774c567db83a9acf2e7c49b3afa8a756c39150f5','445b9f510ea7a28648f8e2e9e2a8023d6eb6b795','ba046cbf003518880f44fee5a7ee43ea326d99e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.150ab5e9c8800932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
