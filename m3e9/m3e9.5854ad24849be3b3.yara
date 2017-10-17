import "hash"

rule m3e9_5854ad24849be3b3
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5854ad24849be3b3"
     cluster="m3e9.5854ad24849be3b3"
     cluster_size="265 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef diple"
     md5_hashes="['ba6e5e09fad719a3c0d5f0d03ab42813', 'cb014825c515ec6bfafc832d7917ba73', 'c31f15263dff2f5b4e194bd174a2c71a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(224256,1024) == "7c94c957c8569a369a9dc8b86dd0901d"
}

