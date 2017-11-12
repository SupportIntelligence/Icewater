import "hash"

rule k3e9_51b9330695a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9330695a31932"
     cluster="k3e9.51b9330695a31932"
     cluster_size="193 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e8175a8372820c558bb7e5e442e2a958', 'ac2de37390c12df3097451b9485d32ed', 'd97ef07ab2eb7495f91a6794f92a02ac']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

