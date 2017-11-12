import "hash"

rule k3e9_38adb8c3c4001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.38adb8c3c4001132"
     cluster="k3e9.38adb8c3c4001132"
     cluster_size="458 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd upatre trojandownloader"
     md5_hashes="['bd255be80f0530e7b77c185290e4550f', '325f7e029ae81a52f94c8fa1bace36f6', '7fbff3426b9c8036e05955a506b5d764']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "17dae5a43bd1300e36c867878c669749"
}

