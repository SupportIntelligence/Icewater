import "hash"

rule m3e9_219716c8d9bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.219716c8d9bb1932"
     cluster="m3e9.219716c8d9bb1932"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="graftor delf malicious"
     md5_hashes="['c9a8a0610f7706fff56d378222d5eeb9', '34f204d87d735aaad47bc05889a1dc1b', '0e5724d3211de55185294c75d3733715']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8215,1027) == "979dae32f2af37a1cd6cade95ba940a4"
}

