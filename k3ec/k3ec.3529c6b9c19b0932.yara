import "hash"

rule k3ec_3529c6b9c19b0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3529c6b9c19b0932"
     cluster="k3ec.3529c6b9c19b0932"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['bc54849c837d31751a930bf2a794c908', 'bc54849c837d31751a930bf2a794c908', 'bc54849c837d31751a930bf2a794c908']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(42496,1536) == "95b382834abdcaec213424d936d7a6ea"
}

