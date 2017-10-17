import "hash"

rule m3ed_531403b999746d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999746d16"
     cluster="m3ed.531403b999746d16"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['225980ed3b727d8ff381a823070e24ab', 'ad755ff44127c655b7b9eeeaf0aa81c8', '2dcf3a1df833a0524c6224bb6d77895d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

