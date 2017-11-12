import "hash"

rule m3ed_4993254ada6fe912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4993254ada6fe912"
     cluster="m3ed.4993254ada6fe912"
     cluster_size="3347 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor palevo backdoor"
     md5_hashes="['45416520678025f505b5d6a9a0358da3', '1384efbcbc210c0b5f1237fe54e8f536', '1b8412ac080871e04d0ccb499d4106ce']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(201988,1045) == "7491b125c71abe23c4429519878a5332"
}

