import "hash"

rule m3e9_3163394ba2221112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163394ba2221112"
     cluster="m3e9.3163394ba2221112"
     cluster_size="91 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vjadtre nimnul wapomi"
     md5_hashes="['a951ac771174763195cce455278d68e8', 'b74b205aa02de568ebcc374e4ed8b1f6', 'c787b6d3b32d040edd038e75ef5f24ff']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

