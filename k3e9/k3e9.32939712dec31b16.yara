import "hash"

rule k3e9_32939712dec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.32939712dec31b16"
     cluster="k3e9.32939712dec31b16"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ccaea1bbbb60dcfd5b95f3c0f7406ac5', '22a7c8fb438ab0b759cb2d7c0f0443b8', 'bee0e23f5f4a0eaf3161b3edb834ce4d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

