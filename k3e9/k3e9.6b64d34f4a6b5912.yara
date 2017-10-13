import "hash"

rule k3e9_6b64d34f4a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f4a6b5912"
     cluster="k3e9.6b64d34f4a6b5912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['141975fc18aefd3dc29ba01aad5177fd', '1c112fd3137e5b545121d907a22d7932', '141975fc18aefd3dc29ba01aad5177fd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

