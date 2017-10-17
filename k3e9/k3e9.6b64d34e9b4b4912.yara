import "hash"

rule k3e9_6b64d34e9b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34e9b4b4912"
     cluster="k3e9.6b64d34e9b4b4912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['adcfec1826e6d23209ff80109988f08e', 'a81fdb20ab96dff4c4831094d4cb3414', 'a81fdb20ab96dff4c4831094d4cb3414']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "1a3f602d02f72071681058059ed6e51c"
}

