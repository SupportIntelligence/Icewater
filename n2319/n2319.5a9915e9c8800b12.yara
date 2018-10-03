
rule n2319_5a9915e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.5a9915e9c8800b12"
     cluster="n2319.5a9915e9c8800b12"
     cluster_size="98"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['a9bb4ea099c7a7df65e217b5a622f713a7ebbf5d','d259fe47223f0887432ca05e442246bc16f50bbc','c78f409b8f70b7a7d7fc093575c5d13cf78eddb6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.5a9915e9c8800b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
