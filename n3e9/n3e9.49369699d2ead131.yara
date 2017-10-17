import "hash"

rule n3e9_49369699d2ead131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49369699d2ead131"
     cluster="n3e9.49369699d2ead131"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi virut advml"
     md5_hashes="['8a8a63d4b3468867a4af02b2d172d308', '56c552834c9b1febdb24c0b3d7606736', '2982eb0f1ce3e18b6c3a2fb14226e60f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(486400,1024) == "fe71d054107cf7ad195afd5a53b3b467"
}

