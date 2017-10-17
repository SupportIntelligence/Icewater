import "hash"

rule k3e9_45b4fc369cbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc369cbb1932"
     cluster="k3e9.45b4fc369cbb1932"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['1133eff1d03cf60e0e3b9a657f7e0d87', '38a155cdea985498f8ca6955b114a0b0', '1133eff1d03cf60e0e3b9a657f7e0d87']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

