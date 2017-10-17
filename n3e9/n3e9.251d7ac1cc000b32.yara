import "hash"

rule n3e9_251d7ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d7ac1cc000b32"
     cluster="n3e9.251d7ac1cc000b32"
     cluster_size="569 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['a244540f60d22cbf702b400e6e33f26e', 'ac8c477a00babd202d69ab7ee844d2ad', '39b6b592e75ef50be74788b561352608']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

