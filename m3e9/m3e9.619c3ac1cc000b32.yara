import "hash"

rule m3e9_619c3ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619c3ac1cc000b32"
     cluster="m3e9.619c3ac1cc000b32"
     cluster_size="731 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['8638edda1c5d994aaf205f801eb24976', '15c4380c6400467edb57938eff81625c', '225f5f228e0dc1361cb6baefb26375a2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

