
rule k26d7_7ed0696f86420120
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d7.7ed0696f86420120"
     cluster="k26d7.7ed0696f86420120"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webprefix xjltf malicious"
     md5_hashes="['55ad64372d67e4da56254e04c91a5ad659420093','d16b271974096fe795bfa8491570debecaed1ed3','1e9e92961f8b4b0704a544be8dc29c30286808dc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d7.7ed0696f86420120"

   strings:
      $hex_string = { 73bb1da2a5792730b306b02229112e31438b2d92954917008336a73209013e21539b3d8285590710932654c2e9f1ced1a36bcd7275a9f7e063d64bd289e1dec1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
