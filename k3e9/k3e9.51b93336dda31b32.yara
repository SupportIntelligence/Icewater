import "hash"

rule k3e9_51b93336dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93336dda31b32"
     cluster="k3e9.51b93336dda31b32"
     cluster_size="325 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d2242112bdccf6b5ed874d10e1102bbc', '0a4fd8a7ba1b082367ed65ac4e43e063', 'ea4cc0c52c1eb0917853304d22c330b0']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

