import "hash"

rule m3e9_316339675deb1112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339675deb1112"
     cluster="m3e9.316339675deb1112"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['c2621cb5f39550c3f79c4c9d8e0e7c80', 'c56044f37b2b97e13ef29c891f4586e6', 'c2621cb5f39550c3f79c4c9d8e0e7c80']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

