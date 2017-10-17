import "hash"

rule m3e7_135e9699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.135e9699c2200b32"
     cluster="m3e7.135e9699c2200b32"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy snojan bdbe"
     md5_hashes="['e491d41807e389057420ff321fed250f', '7ae18f9034a0d7df00e7b2f63cd3a354', '78550ee48eeab654ff80a926e20213f3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(63488,1024) == "2d4a87c4d5ab9520eccb108f5629ba3a"
}

