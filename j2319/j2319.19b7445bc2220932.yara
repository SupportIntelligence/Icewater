
rule j2319_19b7445bc2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.19b7445bc2220932"
     cluster="j2319.19b7445bc2220932"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html phishing infected"
     md5_hashes="['84cbb45bca358ba3ef7abec1f487781a67a4906c','3045c3f2d9286906af95353ac3d93c4da5dbd893','7eeda9d3a4c861ce4cd0b40c0e946f4ed3bc15d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.19b7445bc2220932"

   strings:
      $hex_string = { 3d22746578742f6a617661736372697074223e0d0a2f2f3c215b43444154415b0d0a7472797b696620282177696e646f772e436c6f7564466c61726529207b76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
