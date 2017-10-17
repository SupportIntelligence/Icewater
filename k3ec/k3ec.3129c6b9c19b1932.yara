import "hash"

rule k3ec_3129c6b9c19b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3129c6b9c19b1932"
     cluster="k3ec.3129c6b9c19b1932"
     cluster_size="54 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['62dc0ab50797a04e8f973ac4d4807fdf', '67fc018bb2af3b6864c3e9d2f1c5e800', '62dc0ab50797a04e8f973ac4d4807fdf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(42496,1536) == "95b382834abdcaec213424d936d7a6ea"
}

