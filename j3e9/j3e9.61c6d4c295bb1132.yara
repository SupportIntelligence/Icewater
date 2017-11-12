import "hash"

rule j3e9_61c6d4c295bb1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.61c6d4c295bb1132"
     cluster="j3e9.61c6d4c295bb1132"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pakes jnyb fakeav"
     md5_hashes="['80d7128a3a3354831b808b12cc0c77fc','8f813c8d1a76acb5f137863c1b226778','bfb1505311a050d1f4c0835bfbd2c525']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(131072,65536) == "e5a84840976f936836ee396d38d356da"
}

