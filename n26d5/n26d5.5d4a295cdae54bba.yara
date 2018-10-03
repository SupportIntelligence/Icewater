
rule n26d5_5d4a295cdae54bba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5d4a295cdae54bba"
     cluster="n26d5.5d4a295cdae54bba"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gifq kryptik"
     md5_hashes="['81f420bbeefd181527260d352863708e210f1e01','4e0c21ccac772682233654d74029e36ae28a0163','03a3b48d385955a877405b861c75ae571b9d885c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5d4a295cdae54bba"

   strings:
      $hex_string = { 6bf1ce85491a510f15f739b5586779b9412b4a2869cdfd877652d010aa002d1c326f95970103a7e893dd35d7377e4819777268a31f54dfc5a67bdb6d7aa95c1b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
