
rule k2319_3814d6b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3814d6b9c8800b12"
     cluster="k2319.3814d6b9c8800b12"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['42f53cb4439fe373758004349be98d66fff6a462','a161693a7bc51c6c52d68c266c111a27674eccff','d20b710bf3a0c9d797fd32bb8f86b50ff8646305']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3814d6b9c8800b12"

   strings:
      $hex_string = { 773b666f72287661722059306d20696e206c3379306d297b69662859306d2e6c656e6774683d3d3d2828352e393145322c30784442293c3d28307837462c3836 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
