import "hash"

rule j3e9_05c6dcc295bb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.05c6dcc295bb1112"
     cluster="j3e9.05c6dcc295bb1112"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pakes jnyb fakeav"
     md5_hashes="['20370d481a19ca996c1933c40ef4991c','89aa2f8b276921ac8273ca48e2f5f59a','f085810ec9b6502e14708ba2953f0abc']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(131072,65536) == "e5a84840976f936836ee396d38d356da"
}

