import "hash"

rule m3ed_5b8a8e4dc73b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.5b8a8e4dc73b1932"
     cluster="m3ed.5b8a8e4dc73b1932"
     cluster_size="160 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="chepdu banload agfb"
     md5_hashes="['ca5324c5ed7f1ac916569d8c7efba970', '575cc2c8cdcc09851f66fa80e8536b52', 'c068ec28e3e3eaccf70c0b1078f690a9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(176128,1024) == "f8118e7228db3152380d74d22606ce45"
}

