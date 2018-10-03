
rule k26dd_139694f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26dd.139694f9c9000b16"
     cluster="k26dd.139694f9c9000b16"
     cluster_size="3600"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hackkms hacktool kmsactivator"
     md5_hashes="['b2e17b612bb62c53b56937804707bcfed7ec32f3','a5596b25204e252ca51d1323a73fc8919fb27076','7966600f3f4839c534023cf8a6eefa0069d07090']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26dd.139694f9c9000b16"

   strings:
      $hex_string = { 57538d45fc50e8d57e000085c07c2d8b45fc33d28bcbf7f13bc676208bd78945f88b4d0c8b7d088d720a33c0f3a675058b028945f403d3ff4df875e5685f4449 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
