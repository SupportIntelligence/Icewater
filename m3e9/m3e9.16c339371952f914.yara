import "hash"

rule m3e9_16c339371952f914
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c339371952f914"
     cluster="m3e9.16c339371952f914"
     cluster_size="1805 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup honret zbot"
     md5_hashes="['345f9cd47fb9a55c7ff15e9dcdff1251', '5f9e269a83aca87ba232b9765f9001bc', '345f9cd47fb9a55c7ff15e9dcdff1251']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(139776,1024) == "5e8876e082003050bfc1063612bce02d"
}

