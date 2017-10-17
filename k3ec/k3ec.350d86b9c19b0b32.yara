import "hash"

rule k3ec_350d86b9c19b0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.350d86b9c19b0b32"
     cluster="k3ec.350d86b9c19b0b32"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['6797aa5d8580b5f26dfced8502566b77', 'a1834574b631b0870f64878658afd685', '3199944f724c5b60861f8d33265b57a5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(42496,1536) == "95b382834abdcaec213424d936d7a6ea"
}

