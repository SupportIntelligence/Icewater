import "hash"

rule i3ed_053666e9ce248932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053666e9ce248932"
     cluster="i3ed.053666e9ce248932"
     cluster_size="182"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz accv"
     md5_hashes="['029dcb968189130ccabb30079e5e7f19','046593553331c275823652aeb659ce07','2ab46b4a6803d04b4bc77518cd108ee5']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "2ce7a14e612f014d2098e71f7d61298d"
}

