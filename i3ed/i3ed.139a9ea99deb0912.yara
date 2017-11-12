import "hash"

rule i3ed_139a9ea99deb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.139a9ea99deb0912"
     cluster="i3ed.139a9ea99deb0912"
     cluster_size="2027"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor padodor symmi"
     md5_hashes="['001ab9bc3f73e3cd39d36d0c6d146a12','001fa1da20a70405c9b39c59f7148b54','01d63272d0552bc18e1923c2b9ea2062']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "e16ec7677fd8aa62e40b9e59f876efd6"
}

