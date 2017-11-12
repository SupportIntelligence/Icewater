import "hash"

rule m3e9_4aa2ea4500001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4aa2ea4500001112"
     cluster="m3e9.4aa2ea4500001112"
     cluster_size="293287 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vilsel lamechi riskware"
     md5_hashes="['0061d0f272867c7ee2f5c6fc1e47db31', '00144574b8c79c79f59fc754b5f9c3c9', '0070462c1de26566d66bde7799de1719']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(4096,1024) == "3bd5904065a027e156b4eaa6232d9b16"
}

