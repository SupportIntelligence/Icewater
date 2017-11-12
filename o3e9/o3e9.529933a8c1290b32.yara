import "hash"

rule o3e9_529933a8c1290b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.529933a8c1290b32"
     cluster="o3e9.529933a8c1290b32"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury bdff"
     md5_hashes="['665c8273bef0091a7903da5f07b4d734', '8a798f32e52b867fcdf341211d8492d5', 'b685685d3cbe9362f6a1cba40b0dcec0']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(620544,1024) == "72beb9edbe73061adfcb3345c35a38b8"
}

