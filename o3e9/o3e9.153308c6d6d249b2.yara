import "hash"

rule o3e9_153308c6d6d249b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.153308c6d6d249b2"
     cluster="o3e9.153308c6d6d249b2"
     cluster_size="1401 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr heuristic"
     md5_hashes="['2ca0b379fda0eb5e42a2aefd837ee19f', '3563e5febfbfb94700de8459103658fa', '23169c5a14fecd04198872bb492fea2a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2560037,1061) == "837b575480285c54d29c964d6573128f"
}

