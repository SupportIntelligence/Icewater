import "hash"

rule m3e9_125f291ec6610b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.125f291ec6610b12"
     cluster="m3e9.125f291ec6610b12"
     cluster_size="543 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a720fb3d4d7384dfb95774a4336c7714', '04e0651108071891f610e3a9ae40b3f7', '52a47af1adb66aaac3e3c7dcb5a0d4bf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(25600,256) == "ab8a8f59d26a4d76ef7959266850d80d"
}

