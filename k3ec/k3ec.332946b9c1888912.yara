import "hash"

rule k3ec_332946b9c1888912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.332946b9c1888912"
     cluster="k3ec.332946b9c1888912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['da33f4103e1927a9d5ec03ea2dc31d13', 'dba57602c98b864902208a681182b1e1', '13612089e59d53f81a13bd357aa2ee91']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(43520,1536) == "bed229a33d33f2961e0d20f51268104d"
}

