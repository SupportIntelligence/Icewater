import "hash"

rule m3ef_099d2a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ef.099d2a49c0000b12"
     cluster="m3ef.099d2a49c0000b12"
     cluster_size="20335 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="linkury unwanted zapchast"
     md5_hashes="['081cc48e3b2649c472065c29562e0685', '04f6b75c4328c05b46be740732d31412', '04186b0cb62ff1445abd2fbdf5d26440']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(35840,1024) == "df86c8d402927a3e6f7ac4e6d87c3773"
}

