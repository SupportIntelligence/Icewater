import "hash"

rule p3e9_6198ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.6198ea48c0000b32"
     cluster="p3e9.6198ea48c0000b32"
     cluster_size="503 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['58720a7be461096150fcec27facfe1d0', '1cb23be1c25d20b5f4ed4165dca588ba', '7483a30909831904cef783e2f8f6af22']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(3271828,1061) == "6e6f4836cce1716c86d16a98d267e88c"
}

