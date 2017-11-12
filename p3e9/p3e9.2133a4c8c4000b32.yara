import "hash"

rule p3e9_2133a4c8c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.2133a4c8c4000b32"
     cluster="p3e9.2133a4c8c4000b32"
     cluster_size="681 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['10b686d2acaeee2f9dc3467b5e53b266', '48380db58fcd883ac5f25084e6208fde', '0f82c370615905162e146a3a72303a8d']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(3196943,1025) == "b28fde35cceb540730107b616e88ed9c"
}

