
rule k2319_519f4e59dbd30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.519f4e59dbd30912"
     cluster="k2319.519f4e59dbd30912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script jsredir redirector"
     md5_hashes="['38dc238e7ba0fd0dc539c50e5008bb74dde558bb','da61f250c45aed6823bc9963936357ea4bf661ae','c65c8e1dcd2ce3f617208b284991a3b1aab54a13']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.519f4e59dbd30912"

   strings:
      $hex_string = { 273e0a2f2a203c215b43444154415b202a2f0a766172205f77706d656a7353657474696e6773203d207b22706c7567696e50617468223a225c2f77702d696e63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
