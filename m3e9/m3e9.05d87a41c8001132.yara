import "hash"

rule m3e9_05d87a41c8001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.05d87a41c8001132"
     cluster="m3e9.05d87a41c8001132"
     cluster_size="193 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre kryptik"
     md5_hashes="['cbb765c3775749930001fdf5b6977c97', 'd197da7be8577bfb835577df873fbad5', 'ca3e8da0b0d04e7c133e50d86a2c0650']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "a30f7cf6200d96864cfa9ef0e643a048"
}

