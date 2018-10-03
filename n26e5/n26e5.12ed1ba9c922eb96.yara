
rule n26e5_12ed1ba9c922eb96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.12ed1ba9c922eb96"
     cluster="n26e5.12ed1ba9c922eb96"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner malicious pemalform"
     md5_hashes="['b526330632dab50840f3772edbe56fd737a8d7be','98d3f815283ee0a88bcaa78dac8860a5611e35a9','4bee7eb4d3cf060b38d5f8c91f3247b9dfb6335d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.12ed1ba9c922eb96"

   strings:
      $hex_string = { 74b6891424c744240410b24c00e886c1feff8b46488b564c29c2c1fa0239ea77b68b3580a04f008b6e20a154a04f000fb6560185ed742e84d2bf9cb04c00bbc8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
