import "hash"

rule n3ed_15f2d2eba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f2d2eba6220912"
     cluster="n3ed.15f2d2eba6220912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['cefcf790841877277cebe60fa6ddcb90', 'cefcf790841877277cebe60fa6ddcb90', 'baf0d1c45f89818223910ccbd7cefc3a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(175616,1024) == "7858e5bdec228257b0fded716f7e177d"
}

