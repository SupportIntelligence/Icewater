import "hash"

rule o3ed_7d4f6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.7d4f6a48c0000b32"
     cluster="o3ed.7d4f6a48c0000b32"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['ab9c887f1d1f0ab928f2a1ce74d4b222', 'bf6062cf3aecd74c38555b050d13de5d', 'c836a5fe8c1d96773e0bff8c2712d2b9']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

