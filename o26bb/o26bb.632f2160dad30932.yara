
rule o26bb_632f2160dad30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632f2160dad30932"
     cluster="o26bb.632f2160dad30932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious malwarex"
     md5_hashes="['b90e5016a7ccd614267fe01da81ba65cc3c7d761','fe44194a1acd54443b804bde77ac1c79c05341a6','945912b33b5f582cbaba72ededd57868582e1e78']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632f2160dad30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
