import "hash"

rule i3ed_07bb33e342209116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e342209116"
     cluster="i3ed.07bb33e342209116"
     cluster_size="295"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue symmi bundpil"
     md5_hashes="['017f5e23769230f201cfef47b3826618','030101639f771d3808b2c45f6bf89736','11601104672008bbd3190cc3c3c6f6fd']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "05843457cff4c58c25e3021f3f221ff4"
}

