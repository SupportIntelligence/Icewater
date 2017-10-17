import "hash"

rule k3e9_3c1da849c4010b50
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1da849c4010b50"
     cluster="k3e9.3c1da849c4010b50"
     cluster_size="715 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre zbot jqkn"
     md5_hashes="['a1f1105b1abf806c9647cf80860f8d88', '011a83f64e8cd5184f8a9c38afc70656', '13333375aed2258a28b8d5ce44768a26']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "11398cb3a3813276464ee7f3ebd76ed6"
}

