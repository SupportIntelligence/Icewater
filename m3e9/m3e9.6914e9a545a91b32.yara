import "hash"

rule m3e9_6914e9a545a91b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6914e9a545a91b32"
     cluster="m3e9.6914e9a545a91b32"
     cluster_size="17169 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shifu shiz xambufj"
     md5_hashes="['05a4fbcc73d475a01d277292f4a3c631', '0338ff8a2f9aa7cf1d88ba001ef9cb38', '00eff7c85de98a077fcfa78f860872d1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(103238,1027) == "71ce9cab0784faea36ba55609dbca846"
}

