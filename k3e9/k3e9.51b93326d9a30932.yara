import "hash"

rule k3e9_51b93326d9a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93326d9a30932"
     cluster="k3e9.51b93326d9a30932"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e05ea0a4150feb8fdb689a5d552b4c0c', '0c50bd18ce854729679f597a77678f01', '1ffe9218e6f6b63e4dc8ba9ed879b8c9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

