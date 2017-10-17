import "hash"

rule k3e9_6b64d36b9d6b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9d6b4912"
     cluster="k3e9.6b64d36b9d6b4912"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ac48504b88d40edabd1f7aedf6316fd7', 'bd0671af0f528896c44a68449dfb3d54', 'bd0671af0f528896c44a68449dfb3d54']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,1024) == "fed41aa492b575fa0024f13ad4c5fd5e"
}

