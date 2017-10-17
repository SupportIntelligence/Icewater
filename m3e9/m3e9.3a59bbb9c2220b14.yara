import "hash"

rule m3e9_3a59bbb9c2220b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a59bbb9c2220b14"
     cluster="m3e9.3a59bbb9c2220b14"
     cluster_size="91 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['b921a430bff6cbe48781d864270e9733', 'ae114c288c09a1353c0113ba227cfba2', 'c8730e7d4187aa3133272e3ecc70ea1f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

