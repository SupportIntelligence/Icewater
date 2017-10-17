import "hash"

rule p3ed_29995ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.29995ec1cc000b12"
     cluster="p3ed.29995ec1cc000b12"
     cluster_size="125 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="blakamba trojandropper riskware"
     md5_hashes="['9f5e80d60c342af1f1cc276af41336a7', '472ebf0d06f4ae1c38b3be88f45632bb', 'e14b5f1856ce2d900156965c2b2e86e1']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(5302784,1024) == "8c0bb0ddad65ad8dd5c543190bfe6a8a"
}

