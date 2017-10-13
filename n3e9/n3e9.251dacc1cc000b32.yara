import "hash"

rule n3e9_251dacc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251dacc1cc000b32"
     cluster="n3e9.251dacc1cc000b32"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nimnul vjadtre qvod"
     md5_hashes="['47c4fca84fb52017306382db6cdfcf46', '0516a5af15d37e454287c1bcda7363ee', '37f71f1204f6e2c4e685b51823581da8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

