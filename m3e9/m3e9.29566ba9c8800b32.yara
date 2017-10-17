import "hash"

rule m3e9_29566ba9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29566ba9c8800b32"
     cluster="m3e9.29566ba9c8800b32"
     cluster_size="236 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="small madang madangel"
     md5_hashes="['4bb31bd42dd0a0a8c0bf83b91ab2199c', 'b238fe25a96c22dcc8c982851813c250', 'dd90fb2676dd398968cb6ec1b5b0eaca']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(21720,1042) == "53d6812870249449e4886988f42d0516"
}

