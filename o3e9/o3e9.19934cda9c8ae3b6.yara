import "hash"

rule o3e9_19934cda9c8ae3b6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19934cda9c8ae3b6"
     cluster="o3e9.19934cda9c8ae3b6"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['88d4ce2d371707d5d8ba2c91857fb451', 'cc6a6ba7ddd7ae4b76f7c0c69449b835', 'd1adac22b62c5bebf1e42859cd375bae']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3023235,1025) == "fc45b3f35d97d3d5d7f7dc7995915a6d"
}

