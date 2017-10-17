import "hash"

rule k3e9_69b9a166cd939b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69b9a166cd939b12"
     cluster="k3e9.69b9a166cd939b12"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['4db00810a925a06100f90ecbd866b975', '4db00810a925a06100f90ecbd866b975', '4db00810a925a06100f90ecbd866b975']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,1024) == "f751fc03ac106c581a7746569740097e"
}

