import "hash"

rule m3e9_33b9e849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b9e849c0000912"
     cluster="m3e9.33b9e849c0000912"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swrort elzob zusy"
     md5_hashes="['77af3beb0fb2d872c61154cace76debc', 'b670e18912763536e43191b037256431', '8544dc6561c4adc609702aa182a6e32d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(69632,1024) == "28b0354c32935ddf92ccdc28236a4ce2"
}

