
rule n26d5_5b28299d9997eb92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5b28299d9997eb92"
     cluster="n26d5.5b28299d9997eb92"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['c6fd675344e5df0ced34f270008bc9d45defc76a','bce9b4731e794a2b0ca7ce1385a5604410d26ea6','20fd9457b70b698af5f0ac11ac0dbbd32a80b3d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5b28299d9997eb92"

   strings:
      $hex_string = { 1baeda4153867511e962d4183e054b47ce959bbfaac181b61664f560b56834e4454e022d2142d08a0ba88b07b91765b3c9735af07ec6ca725d77d9b25f4f1e70 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
