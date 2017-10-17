import "hash"

rule k3e9_53379fe2d9929912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53379fe2d9929912"
     cluster="k3e9.53379fe2d9929912"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['83be018b05987846745264d845711cf1', '83be018b05987846745264d845711cf1', 'bc2dd4e5cec4f2ed03f1bab2d02e3c1b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1280) == "da879da1717d791298f0d119c43f9f2e"
}

