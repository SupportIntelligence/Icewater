
rule n2319_291b308dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.291b308dc6220b12"
     cluster="n2319.291b308dc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer bitcoinminer"
     md5_hashes="['6548990464ba197eb836cf64f75b110012380cdd','fe6cb33047a6c1039d5d292790175c2c9f2cf11f','7f5a241bfc3887ed3b7d9c2a21c295d3f57fef1b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.291b308dc6220b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
