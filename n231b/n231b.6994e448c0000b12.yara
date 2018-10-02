
rule n231b_6994e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.6994e448c0000b12"
     cluster="n231b.6994e448c0000b12"
     cluster_size="98"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer miner script"
     md5_hashes="['63569a39a5f203d436c31d55cc0b5ad703472828','63b90ca46298bcbc1879ebd953e70bcaf7728fd2','da3863dcf82764359b1d5f8d1314c091a5506caf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.6994e448c0000b12"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
