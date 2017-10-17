import "hash"

rule n3e9_33b23092d7bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33b23092d7bb1912"
     cluster="n3e9.33b23092d7bb1912"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="foax kryptik malicious"
     md5_hashes="['23dca9409ee139110a6332309b11c8bd', '2ad2a367b7d3eb690e4a0fba559a483a', '75d8a8f79e5c669df6bfa9601e7df160']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "5871d25b2156944140f121c756cf1c6b"
}

