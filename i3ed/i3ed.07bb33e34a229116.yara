import "hash"

rule i3ed_07bb33e34a229116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e34a229116"
     cluster="i3ed.07bb33e34a229116"
     cluster_size="248"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue symmi bundpil"
     md5_hashes="['01d9f1590410f43fcbbd4e823063a337','03a816bd27cd81610a31d8ff46068676','1419a5cb4d35478c72ec482a6bb082ca']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "05843457cff4c58c25e3021f3f221ff4"
}

