import "hash"

rule k3e9_291a1ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291a1ce9c8800b12"
     cluster="k3e9.291a1ce9c8800b12"
     cluster_size="2677 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious delphi"
     md5_hashes="['2640a386e2737a828e00b94ce2d498d8', '0eca4f1cb6c998fb2c10d979834741b9', '23cfdfc66f869cd202b2868934d5b3a3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13312,1024) == "b50382ecdb94a96597d82a761efbea09"
}

