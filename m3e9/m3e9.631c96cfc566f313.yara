import "hash"

rule m3e9_631c96cfc566f313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c96cfc566f313"
     cluster="m3e9.631c96cfc566f313"
     cluster_size="121 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['2bbc8591eedaf267fe3cd55c43bc0cab', 'c065daca8047cb1b5ee5f206d3c2fea7', 'abef6ac74206ca0428ca0bde83c47920']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(178688,1024) == "1596c37d7b83e8d61aec91f1f8c7700f"
}

