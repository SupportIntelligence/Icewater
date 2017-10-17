import "hash"

rule m3e9_611a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611a9cc9cc000b12"
     cluster="m3e9.611a9cc9cc000b12"
     cluster_size="258 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['ccb2ce52f58187c740a44226b13d6fad', 'cd10e3d85290bbcb22718a6b57c1b618', 'b3302f7cd24c59ad49db9fd5bd02ab2b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(72192,1024) == "14dde33989693b4355285520cc00d3a5"
}

