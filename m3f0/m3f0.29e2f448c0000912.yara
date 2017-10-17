import "hash"

rule m3f0_29e2f448c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.29e2f448c0000912"
     cluster="m3f0.29e2f448c0000912"
     cluster_size="356 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt xpack bayrobcrtd"
     md5_hashes="['7d92d5a30f45d6c31701f6102def37e3', 'd13cfc44ed74484f970c0d30a3d1f628', '2307b80768c09b6af16462a5a55dc231']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(43407,1081) == "0774b7b184022f4fff3c3179eb29d2e6"
}

