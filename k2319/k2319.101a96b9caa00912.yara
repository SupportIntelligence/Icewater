
rule k2319_101a96b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101a96b9caa00912"
     cluster="k2319.101a96b9caa00912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b8b14fc063d987a60b5e22d59a7d208c255330ec','e5ec5ff049c880a67727b489bb0be5fd19728368','5230f0ae8c510991de9460fb31f0e9e53556acd4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101a96b9caa00912"

   strings:
      $hex_string = { 646f773b666f72287661722044345420696e2055336a3454297b6966284434542e6c656e6774683d3d3d282830783146372c312e3136354533293e307839423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
