import "hash"

rule i3ed_07bb33e342229116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.07bb33e342229116"
     cluster="i3ed.07bb33e342229116"
     cluster_size="298"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue symmi bundpil"
     md5_hashes="['001983ca5ce9f909a347d38dc8ab5995','013ab6010c367433a2d1ef814c1af09f','0e5260826cd35bbe7093844b1ff5768f']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "05843457cff4c58c25e3021f3f221ff4"
}

