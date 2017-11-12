import "hash"

rule m3e9_711c52d2d9e39912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.711c52d2d9e39912"
     cluster="m3e9.711c52d2d9e39912"
     cluster_size="642 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c7a8fab836b16379716ff39baffe18af', 'be17b848d908e6df0018a65a1472217b', '313e06ab69fa6b8bb2be506fd9c37511']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(9216,1024) == "fbad040c0983c3d7c7a05e828ed77efb"
}

