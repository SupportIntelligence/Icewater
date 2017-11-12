import "hash"

rule i3ed_053666e9ee2c8932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053666e9ee2c8932"
     cluster="i3ed.053666e9ee2c8932"
     cluster_size="201"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz accv"
     md5_hashes="['004f181fc4cf8ad8a9e2fcb2bc725a42','01ca5b9d7769c012558ca9cf26738403','1d027d03d5ee22d470357259d5d90f8d']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "2ce7a14e612f014d2098e71f7d61298d"
}

