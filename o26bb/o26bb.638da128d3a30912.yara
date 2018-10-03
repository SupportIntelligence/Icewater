
rule o26bb_638da128d3a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.638da128d3a30912"
     cluster="o26bb.638da128d3a30912"
     cluster_size="128"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious softcnapp"
     md5_hashes="['31f9cf3373e09a10eac353243210dd3a60865e88','e71459e10167d4a8cabc8fa2399eaa12ce712291','ef670bd24fd2077648ccbe18ae36ba0eabe575c4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.638da128d3a30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
