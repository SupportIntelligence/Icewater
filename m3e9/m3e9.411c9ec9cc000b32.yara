import "hash"

rule m3e9_411c9ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c9ec9cc000b32"
     cluster="m3e9.411c9ec9cc000b32"
     cluster_size="85 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['d5a5a013ce6ac17e10043a51ee2eb657', 'bed00a482d0980a392fae1f0727fea65', 'bde476154aa24137fd13d20b6c35bfc8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1024) == "bbba8d45598f83db623d488a1ac2de1e"
}

