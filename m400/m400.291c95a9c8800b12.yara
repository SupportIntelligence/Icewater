import "hash"

rule m400_291c95a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.291c95a9c8800b12"
     cluster="m400.291c95a9c8800b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['a1d61eb1ca8769828b9ec10b834a05d2', 'a1d61eb1ca8769828b9ec10b834a05d2', '7bd9513347a2a7fd4d460e008db3856a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(14336,1024) == "9e6cead361e0acd9a574017736bb5643"
}

