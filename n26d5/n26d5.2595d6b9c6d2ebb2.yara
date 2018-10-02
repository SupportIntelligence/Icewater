
rule n26d5_2595d6b9c6d2ebb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2595d6b9c6d2ebb2"
     cluster="n26d5.2595d6b9c6d2ebb2"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['ef0355555c76fb812e6c4a46baca74c02fdc34e3','a28a421d3055fc8b9835426bf448cf87ea64d904','8fe0e8d6b36fe44b1c27a89ab3db8e5fbb2ff577']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2595d6b9c6d2ebb2"

   strings:
      $hex_string = { 2bf3a477c48b316e64ea1c13f7c06790a9a605b4074e1727d9e321d5964bda023340698675307d5a54dcf21e94521ae6ca7b705e141e0a7e0d6cbaf888c5e75c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
