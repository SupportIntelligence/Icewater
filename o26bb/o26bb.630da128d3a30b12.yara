
rule o26bb_630da128d3a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.630da128d3a30b12"
     cluster="o26bb.630da128d3a30b12"
     cluster_size="102"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['c129ee2a4568c782d60f8c3340c35f7a0b42762a','ffa898834fae12aa93743c45b4369f0c91a5feb7','19c5033e54edb49653e689b3a31e8016cc2b13af']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.630da128d3a30b12"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
