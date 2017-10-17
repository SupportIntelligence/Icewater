import "hash"

rule k3e9_6b64d34f8acb5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8acb5912"
     cluster="k3e9.6b64d34f8acb5912"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['49616dd3c05fb99d6adc09ed92602a86', 'c948950da324ad0e8cc804dae1a65a8e', 'c948950da324ad0e8cc804dae1a65a8e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7216,1036) == "27a10cb18182bb90bc5569da36fb9e39"
}

