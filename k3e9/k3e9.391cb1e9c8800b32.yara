import "hash"

rule k3e9_391cb1e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391cb1e9c8800b32"
     cluster="k3e9.391cb1e9c8800b32"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['d7398da98a6930ecbfb1d6e9fa0d2c28', 'a889a4243b64809d602d2d5e9726b770', 'e38bf0363230dd7b536910661cb670d3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1195) == "482beaebbdc1ed3d7533b440ec3ba87c"
}

