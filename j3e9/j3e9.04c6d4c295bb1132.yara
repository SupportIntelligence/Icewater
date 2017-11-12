import "hash"

rule j3e9_04c6d4c295bb1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.04c6d4c295bb1132"
     cluster="j3e9.04c6d4c295bb1132"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pakes jnyb fakeav"
     md5_hashes="['00825c382848385efcfd2236461d87fd','03aca6848ccb98287049642633115bb5','cca25eaa2d2f3dad1d4278d327dd8613']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(131072,65536) == "e5a84840976f936836ee396d38d356da"
}

