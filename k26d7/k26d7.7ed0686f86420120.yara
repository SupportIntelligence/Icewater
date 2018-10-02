
rule k26d7_7ed0686f86420120
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d7.7ed0686f86420120"
     cluster="k26d7.7ed0686f86420120"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious webprefix"
     md5_hashes="['69dd89a2c2ca7c66931c7e95d05569663f35e25a','ce9d58274684dc2c735c4e1c97b4f13ba7c5e460','8b7782ffbc6bbed5333a5c2cc609b65a98d74f7a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d7.7ed0686f86420120"

   strings:
      $hex_string = { 73bb1da2a5792730b306b02229112e31438b2d92954917008336a73209013e21539b3d8285590710932654c2e9f1ced1a36bcd7275a9f7e063d64bd289e1dec1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
