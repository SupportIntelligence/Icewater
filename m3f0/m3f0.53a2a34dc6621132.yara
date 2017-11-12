import "hash"

rule m3f0_53a2a34dc6621132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.53a2a34dc6621132"
     cluster="m3f0.53a2a34dc6621132"
     cluster_size="4916 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="gepys kryptik bcig"
     md5_hashes="['2777b674a15ae182bc6c94a77c733f73', '11203d36a102793ec22a415750706ab5', '23d2333ce40b984cfac0279dc9b73dee']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "750e8917afbd19751811b489e0ae951d"
}

