
rule o26bb_6184a1b0dfa30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6184a1b0dfa30932"
     cluster="o26bb.6184a1b0dfa30932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['c11ee4e9619934c2adb747c0e29172348c69342a','0ff5e5f0f9720d6c3dc3cda6f85d42683104ab9c','1c6c3a06eee5c7bae1ffe0a1de3b2da437dabe0a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6184a1b0dfa30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
