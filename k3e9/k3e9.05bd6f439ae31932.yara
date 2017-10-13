import "hash"

rule k3e9_05bd6f439ae31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05bd6f439ae31932"
     cluster="k3e9.05bd6f439ae31932"
     cluster_size="1677 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="fdld nitol dropped"
     md5_hashes="['65b5a87a73c55439234da986a76cec04', '4e6379cb5b6dda10f398f7dc18f4202a', '54ba944dc408e3a7618ec17b4f0cfcf2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "c5999b2aae920e6fc825cd5123f52641"
}

