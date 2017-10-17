import "hash"

rule m3e9_5db45152a9716f32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5db45152a9716f32"
     cluster="m3e9.5db45152a9716f32"
     cluster_size="160 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbkrypt autorun"
     md5_hashes="['bc8975a40d698a760a442928cc766518', '02770d9d9eef1122532995c897deb695', 'e458f9ee26c2954ba4faec6c32d013f0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(155648,1024) == "31aa08ac108416cba21955a2a1bef7f8"
}

