
rule o26bb_632fa125dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632fa125dda30912"
     cluster="o26bb.632fa125dda30912"
     cluster_size="315"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious aeahd"
     md5_hashes="['c91c1c8dad90f36a2142f38a8dd6ec568163c1ca','bbfa3539ed296b8ae05c5185042133f787a3c86d','d8bcd11d3d0c30c4355c0238f3f022bca7e5a55e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632fa125dda30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
