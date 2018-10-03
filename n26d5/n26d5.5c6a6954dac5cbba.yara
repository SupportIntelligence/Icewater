
rule n26d5_5c6a6954dac5cbba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5c6a6954dac5cbba"
     cluster="n26d5.5c6a6954dac5cbba"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gifq kryptik"
     md5_hashes="['fff4817e5ef37af93173c3cb286bac5448b96042','4a8f5c420af12d49fae6a8d0f70cc8be77618e3f','627085291c66a7e035f9186cbb92fd89f3d871e9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5c6a6954dac5cbba"

   strings:
      $hex_string = { 6bf1ce85491a510f15f739b5586779b9412b4a2869cdfd877652d010aa002d1c326f95970103a7e893dd35d7377e4819777268a31f54dfc5a67bdb6d7aa95c1b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
