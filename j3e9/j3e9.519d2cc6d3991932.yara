import "hash"

rule j3e9_519d2cc6d3991932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.519d2cc6d3991932"
     cluster="j3e9.519d2cc6d3991932"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre bublik generickd"
     md5_hashes="['c23220a16bff94384942839f2bcc50ce', 'c23220a16bff94384942839f2bcc50ce', 'd961d66b897fb0dcb9d9a9e335e3f830']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 4096 and filesize < 16384 and 
      hash.md5(7680,1152) == "40a1e433734db8c0845a76d1e1c3b28a"
}

