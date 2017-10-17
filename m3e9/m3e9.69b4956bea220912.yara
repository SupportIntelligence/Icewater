import "hash"

rule m3e9_69b4956bea220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.69b4956bea220912"
     cluster="m3e9.69b4956bea220912"
     cluster_size="353 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="injector heuristic malicious"
     md5_hashes="['cd1c5ca2a4b04d2dfa7de673229a15f5', '7bebee6a0478fde9e4c4559fc2b9d957', 'aaaf501aa3c2d415fe53ba63bec729a4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(133120,1536) == "f1f9508e5154673eee31947f1c08aadb"
}

