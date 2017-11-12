import "hash"

rule o3e9_1579ac6a9ac3691a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1579ac6a9ac3691a"
     cluster="o3e9.1579ac6a9ac3691a"
     cluster_size="206 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['723e92c759e79c78bbe4788bce36f470', 'a4f391ef4888a87416674a3850175cf6', 'bcde0d409e6784fed0bfea36d3b293f1']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(100352,1024) == "b6f6302223b91cd0a771ded61568c051"
}

