import "hash"

rule k3e9_6b64d34f9a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9a6b5912"
     cluster="k3e9.6b64d34f9a6b5912"
     cluster_size="251 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['0372a8e467917e83a27dcfdb4cb880b7', 'dbbc3b0de8f66cd90ca0071d85d6c306', 'a8dfc33df54d9b00222644cfe144aaa7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

