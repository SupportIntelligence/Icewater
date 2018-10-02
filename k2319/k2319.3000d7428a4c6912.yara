
rule k2319_3000d7428a4c6912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3000d7428a4c6912"
     cluster="k2319.3000d7428a4c6912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script cmiwair"
     md5_hashes="['0d47001f108fcda249bbfbac018aec9f19f438be','74ad63ee3778b23579dc4b9bf6de806c35e710c8','3140ed05af5b2c5fff529f72535c32c715e70106']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3000d7428a4c6912"

   strings:
      $hex_string = { 646f773b666f72287661722073396820696e204534503968297b6966287339682e6c656e6774683d3d3d282833342c3078314343293e35332e3f2835382e2c36 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
