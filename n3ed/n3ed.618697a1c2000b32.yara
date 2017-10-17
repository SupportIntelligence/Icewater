import "hash"

rule n3ed_618697a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.618697a1c2000b32"
     cluster="n3ed.618697a1c2000b32"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['a8f0c784d82f779fc3031e7b8324f9cf', 'b179e32af7962b8a416f7365398965e7', 'cc0316ec910e3dd1b023cfc6c775ce7c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(167936,1027) == "6bf10b6d9fc6a8c45442af9ada0d5e5a"
}

