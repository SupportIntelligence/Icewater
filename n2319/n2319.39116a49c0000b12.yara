
rule n2319_39116a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39116a49c0000b12"
     cluster="n2319.39116a49c0000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer miner script"
     md5_hashes="['753cbc0d47cc40a565714560496dc0491141f574','3bfa3182982c86a9aaf08c56a74af806bfb078d1','f7c06f0ffe6031f7140c2cadd92595812e96e454']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39116a49c0000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
