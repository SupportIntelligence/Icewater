import "hash"

rule m3e9_7954c5afc54ee3b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7954c5afc54ee3b2"
     cluster="m3e9.7954c5afc54ee3b2"
     cluster_size="72 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus chinky pronny"
     md5_hashes="['c07e819817ac5ee4556e408fe66e2326', 'e1b886bf10bfce364f28ae54efe171ae', 'a099ccbaab253b6c5c91f022686990a7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100352,1024) == "52a76525ed4f1368f150bf47c685cdfb"
}

