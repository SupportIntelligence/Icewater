import "hash"

rule m3e9_611e97a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e97a9ca000b12"
     cluster="m3e9.611e97a9ca000b12"
     cluster_size="401 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['d03997d340ae505211acde016ff91f0d', 'd8852db7ebeb927aaaccb564ba7f1014', 'b313672ee15cd7efea74220c56fe9071']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73291,1029) == "da5ab260d3f3b2aa7508f7dfc1ddb857"
}

