
rule n2319_139b1289c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139b1289c8000932"
     cluster="n2319.139b1289c8000932"
     cluster_size="69"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['66837c6b80a9a5a4d7274af0d649bfbc9ba9afa6','0b9ee99c10bd427909f1acde8d6bf4dbf894bd71','857623f7e461e0c1e60f22d7aafe696cd27c5a4f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139b1289c8000932"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
