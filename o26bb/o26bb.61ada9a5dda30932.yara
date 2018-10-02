
rule o26bb_61ada9a5dda30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.61ada9a5dda30932"
     cluster="o26bb.61ada9a5dda30932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['eb926abfafb48e21ef91173ea88c1475868c63ef','191f39cb2ae771a47d88303f1947516ab7e3e2fb','874abcad23065a280bed6e692a235fbe55783eed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.61ada9a5dda30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
