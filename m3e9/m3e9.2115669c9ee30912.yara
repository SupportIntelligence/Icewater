import "hash"

rule m3e9_2115669c9ee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2115669c9ee30912"
     cluster="m3e9.2115669c9ee30912"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran jorik"
     md5_hashes="['4a8cab5827d0584b5970a38d00133886', 'a29ee4ac58614e1fe7b8df7356c785ae', 'b43a30bc04ef4bd40b7f903a09927a27']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(142336,1024) == "e340fc1bae100897d6708a72a46ba4b8"
}

