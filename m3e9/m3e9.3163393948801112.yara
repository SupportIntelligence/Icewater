import "hash"

rule m3e9_3163393948801112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163393948801112"
     cluster="m3e9.3163393948801112"
     cluster_size="15295 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob sality"
     md5_hashes="['015e1cbafcf8d97ec4f10242360d6384', '002fbaba50eea7a5109fcb48393873a5', '0d1a2173043dea0f384ddbdc0194ed14']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(59392,1024) == "0d837d38e03a6ccb900ba9f43eb69222"
}

