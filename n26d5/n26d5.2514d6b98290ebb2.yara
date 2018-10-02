
rule n26d5_2514d6b98290ebb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2514d6b98290ebb2"
     cluster="n26d5.2514d6b98290ebb2"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy genx heuristic"
     md5_hashes="['9cfb52d3276c24cdca82636287d9d8297ad88e6d','7f77404f79f86a1c6c31b796995ee6827ab772fe','813b48a52681c7893cb4e5c68b43b4d21f5795a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2514d6b98290ebb2"

   strings:
      $hex_string = { 1baeda4153867511e962d4183e054b47ce959bbfaac181b61664f560b56834e4454e022d2142d08a0ba88b07b91765b3c9735af07ec6ca725d77d9b25f4f1e70 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
