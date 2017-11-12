import "hash"

rule n3f0_3114a3cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.3114a3cbc6220b12"
     cluster="n3f0.3114a3cbc6220b12"
     cluster_size="9037 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor graftor injector"
     md5_hashes="['0824f7c4670e7004721a83e8cdcf632c', '15e97cb45b09ab0eb79cde243bf34e31', '17d26bc5d4da99510d287c7cabb7fec6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(37120,1152) == "cbba5e0d0b0fc6e38ae73b71a542bb3f"
}

