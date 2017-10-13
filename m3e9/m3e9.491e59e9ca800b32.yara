import "hash"

rule m3e9_491e59e9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491e59e9ca800b32"
     cluster="m3e9.491e59e9ca800b32"
     cluster_size="152 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="conjar vobfus wbna"
     md5_hashes="['ef676ae1e537da645b9e3e9a91344abb', 'c7d478712c92754c8848c9616305c99a', '0031335ddaf17e1dede6b8ce8cb6af07']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(84992,1024) == "5625748851a549882834d9b45008491b"
}

