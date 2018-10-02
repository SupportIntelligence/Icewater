
rule k2319_5a158699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a158699c2200b12"
     cluster="k2319.5a158699c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8afc2d844a20f1edd977799c7184e05b267edd2f','95cb1b86988c42117672beec911554f908adde11','5fb2c86a17bd8817f4fcf59a6ab37134b3d17da2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a158699c2200b12"

   strings:
      $hex_string = { 465b515d213d3d756e646566696e6564297b72657475726e20465b515d3b7d76617220583d2835353c283134332e2c3078313243293f2836302e2c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
