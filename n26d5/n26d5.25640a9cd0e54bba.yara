
rule n26d5_25640a9cd0e54bba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.25640a9cd0e54bba"
     cluster="n26d5.25640a9cd0e54bba"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="obfus kryptik malicious"
     md5_hashes="['6321ece80c046a966cd971cf5535622b362b7c96','af6805493b142c20a93010f681e109f3c7662814','7a16d44668c23be5afc684c48ec145eaa5d1dda7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.25640a9cd0e54bba"

   strings:
      $hex_string = { 6bf1ce85491a510f15f739b5586779b9412b4a2869cdfd877652d010aa002d1c326f95970103a7e893dd35d7377e4819777268a31f54dfc5a67bdb6d7aa95c1b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
