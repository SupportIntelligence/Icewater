import "hash"

rule k3e9_6b64d34f0b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f0b6b5912"
     cluster="k3e9.6b64d34f0b6b5912"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['6ad3ee0134c669e04a6378c0030d73f3', 'd49d14b496f7bac85534039dcbb60165', '5ddf56766312cde909104a9f320b60be']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

