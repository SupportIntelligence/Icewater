import "hash"

rule o3f0_4919959bc2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.4919959bc2200b12"
     cluster="o3f0.4919959bc2200b12"
     cluster_size="2055 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy bitcoinminer risktool"
     md5_hashes="['03a7311392d33b53b241a1a90b67c276', '0194fd739f04242ef54313c3a4b8e3a6', '27cca8195eddd8ca4452c3f5b2279366']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(802816,1024) == "37c626b535dc15ae2ea6a560d57a9561"
}

