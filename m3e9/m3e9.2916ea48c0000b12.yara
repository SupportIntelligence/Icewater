import "hash"

rule m3e9_2916ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2916ea48c0000b12"
     cluster="m3e9.2916ea48c0000b12"
     cluster_size="486 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor atros bejkv"
     md5_hashes="['ac81e51b3ba9b1850f3a2212f113df51', 'd396a37a8cbe0621ab872e553497ef33', '86981e21b9363ebbbe176c6dceaab202']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(60928,1280) == "196b43ba1999a55509ce196108f520b4"
}

