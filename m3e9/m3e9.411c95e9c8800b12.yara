import "hash"

rule m3e9_411c95e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c95e9c8800b12"
     cluster="m3e9.411c95e9c8800b12"
     cluster_size="280 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['bbac4a7a284afa24ba27f5c5c96b31dd', 'acaacf9cfb808306ee5eb3645fa3bb57', 'a79f61ceadb1f6c9df7dbc0d6ca2c399']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100864,1485) == "e2154669906715fd9e8b6ec07c4ee2f3"
}

