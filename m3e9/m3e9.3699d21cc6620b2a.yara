import "hash"

rule m3e9_3699d21cc6620b2a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3699d21cc6620b2a"
     cluster="m3e9.3699d21cc6620b2a"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut prepender shodi"
     md5_hashes="['d716d0909b72d361453418c73a151354', 'd725989aa5a5a73ae741333158970b4d', 'a35be16fcbf039a567a1f68fe3c84ea6']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "8e58efdccc5d126553629034a59cc997"
}

