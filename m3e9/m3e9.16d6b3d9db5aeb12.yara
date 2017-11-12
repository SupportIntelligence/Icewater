import "hash"

rule m3e9_16d6b3d9db5aeb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d6b3d9db5aeb12"
     cluster="m3e9.16d6b3d9db5aeb12"
     cluster_size="97 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="carberp shiz kazy"
     md5_hashes="['ba40896190c72a5c475595e67ea7587a', 'd577a1f1d9471cc694a3d39e25fea772', '26a9919e2a203bfcb10616a839c91f14']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(205824,1280) == "ef1010ada47b5bbe0a045c7fc3dd45bb"
}

