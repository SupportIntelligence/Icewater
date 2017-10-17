import "hash"

rule k3e9_61ee4d4ec6b444de
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.61ee4d4ec6b444de"
     cluster="k3e9.61ee4d4ec6b444de"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c7dd8782098fcc52b5ff0b5d5777d3fd', 'b42449d38b6987aacfd8d1125811cb47', 'b42449d38b6987aacfd8d1125811cb47']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13824,1024) == "365908a00dc8e07cf813c5993d6b08b3"
}

