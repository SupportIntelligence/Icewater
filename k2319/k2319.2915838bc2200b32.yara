
rule k2319_2915838bc2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2915838bc2200b32"
     cluster="k2319.2915838bc2200b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik script"
     md5_hashes="['a1f0d518f7eece27413ac24b83994312ae6f8697','79699a2642c4dc900c746f798ff5d64eb334313a','21f76045de39b3e2c60197ac1636f9686567420b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2915838bc2200b32"

   strings:
      $hex_string = { 31342c30783939292929627265616b7d3b7661722050397730673d7b27503667273a66756e6374696f6e28792c4d297b72657475726e20797c4d3b7d2c277137 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
