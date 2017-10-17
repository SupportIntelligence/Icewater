import "hash"

rule m3e9_4114bb29c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4114bb29c8800b32"
     cluster="m3e9.4114bb29c8800b32"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['779a529a6200550f427275ee7aa8f988', '10ce7213c7d21c7300b9be2fb05188d8', '1aead6e0fec4f269fad1d9fa31bd1bbf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81408,1280) == "8f11f1406d481de44626ff778effb09b"
}

