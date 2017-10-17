import "hash"

rule o3e9_11069099c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.11069099c2200b32"
     cluster="o3e9.11069099c2200b32"
     cluster_size="214 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper bjrqpg"
     md5_hashes="['72c925669eabc9073d72b2670e295c42', 'e33c272022c8c75e43bf07685ed6ac17', 'be1d302d1911b78048772284118f7967']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1834008,1048) == "48f3f9e3a8617ae1493805d784756677"
}

