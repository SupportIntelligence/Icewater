import "hash"

rule m3e9_29567ba1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29567ba1c2000b32"
     cluster="m3e9.29567ba1c2000b32"
     cluster_size="589 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="madangel small madang"
     md5_hashes="['a045885f4e35e059f75f3f5081250ce4', 'b5e5c36919058e694ff0ecafa38639dd', 'b120341831724b9a0ff02c7a981eca7e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(21720,1042) == "53d6812870249449e4886988f42d0516"
}

