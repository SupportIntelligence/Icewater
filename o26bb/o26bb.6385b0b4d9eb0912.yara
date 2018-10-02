
rule o26bb_6385b0b4d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6385b0b4d9eb0912"
     cluster="o26bb.6385b0b4d9eb0912"
     cluster_size="47"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['73c2869ac2f798bb383e186aae7cc218f338f65f','0ef8f4249a28c74318625ad9ad40f5384176f5ba','6b917963ea0d6a29d777f2d897cbbd452a38aa5f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6385b0b4d9eb0912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
