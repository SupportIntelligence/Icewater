import "hash"

rule k3e9_6bb1e438c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6bb1e438c0000912"
     cluster="k3e9.6bb1e438c0000912"
     cluster_size="237 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp small trojanclicker"
     md5_hashes="['d28ea8b555cbe7d0560cb171aa78d0e3', 'a13e8e1782cdbe6b6b977c6a56567603', 'dee263c35bb80a6f8bae00db074d2860']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

