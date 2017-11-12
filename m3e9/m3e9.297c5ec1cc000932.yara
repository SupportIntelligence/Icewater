import "hash"

rule m3e9_297c5ec1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c5ec1cc000932"
     cluster="m3e9.297c5ec1cc000932"
     cluster_size="22901 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0b61d191337b3d7972d7f6180a11a817', '01b3a4f320d5177f4df6416a4d5703d9', '05dc2944ada6e7faad74e55fdf406990']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(5376,1088) == "28c561f0955cd72a51673e04ee096f3e"
}

