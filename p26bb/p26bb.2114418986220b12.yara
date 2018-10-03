
rule p26bb_2114418986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.2114418986220b12"
     cluster="p26bb.2114418986220b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nymeria malicious generickd"
     md5_hashes="['c689f048514f049845a251d65a4c540885feceb8','01a2b0152193d81bcf98ecfa19d7bb191e476391','8d066e624ea796dc9f5a835a6992a324cf2975e3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.2114418986220b12"

   strings:
      $hex_string = { 869b001a883b46112260d5c79e8214404867bdc227a7756b6a9f0ad989c1c052dce29c413769cb6ccc6d1c640c7deda158b0b849f829c539e0572bb90fd0deaa }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
