import "hash"

rule m3e9_0eb13616d8b59912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0eb13616d8b59912"
     cluster="m3e9.0eb13616d8b59912"
     cluster_size="544 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="codecpack kazy zbot"
     md5_hashes="['61278f752b7ef4588b63558b6b77c136', 'a9456370842e9e9c222d7a06d3b14ce1', 'af368d60c840656d86ba5457492166eb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(194048,1280) == "6c792b2f9df88b497d6eb907cf065d6c"
}

