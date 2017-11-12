import "hash"

rule o3e9_153368c69692799a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.153368c69692799a"
     cluster="o3e9.153368c69692799a"
     cluster_size="335 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['a97756a23c14a2de13281b2a86753373', '66c936b66885693adac934025a4e3f51', 'a49fa6a89bca059eb6526b0d70f44474']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(11274,1025) == "203c3db9765747496b6eb91f2dc587c9"
}

