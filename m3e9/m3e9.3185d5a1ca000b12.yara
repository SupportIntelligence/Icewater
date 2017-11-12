import "hash"

rule m3e9_3185d5a1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3185d5a1ca000b12"
     cluster="m3e9.3185d5a1ca000b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b806710777f4eca66c2fb9f56c17c509', '9dcdf778256e56a704c2bc763c0c1ddc', 'b806710777f4eca66c2fb9f56c17c509']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

