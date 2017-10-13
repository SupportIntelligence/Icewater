import "hash"

rule n3e9_251d2cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d2cc1cc000b32"
     cluster="n3e9.251d2cc1cc000b32"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nimnul vjadtre qvod"
     md5_hashes="['a44a69ebab89dafe8dbcbdbd600c4995', 'c47a2ff9f23bb45abfe237e52fe95558', '897389776c6430911ad896e4cc6b2670']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

