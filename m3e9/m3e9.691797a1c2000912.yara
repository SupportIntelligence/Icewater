import "hash"

rule m3e9_691797a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691797a1c2000912"
     cluster="m3e9.691797a1c2000912"
     cluster_size="2333 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['05674030cb3b1fe5a95a02cdf364d132', '67cb70908f26835020b927e33e924118', '8009097ab3f71b6375a93af682c27295']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74752,1024) == "9dd737489d4f545899488dd359173093"
}

