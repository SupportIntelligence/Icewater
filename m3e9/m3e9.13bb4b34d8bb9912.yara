import "hash"

rule m3e9_13bb4b34d8bb9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13bb4b34d8bb9912"
     cluster="m3e9.13bb4b34d8bb9912"
     cluster_size="234 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic zbot shipup"
     md5_hashes="['d7a46e90598721293b24cc1dac635721', 'c0413910b9e0590851f4f8afa8e06b84', 'd7966d88e2afd8230f74159c3886476f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(195072,1024) == "35fa0911c1dc9d1142d82b55893c4a5f"
}

