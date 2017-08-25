import "hash"

rule k3e9_6b64d36b986b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b986b5912"
     cluster="k3e9.6b64d36b986b5912"
     cluster_size="70 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['f5e857bca60e7130aa62e54287fc845a', 'add41493cd618896861be438f91140a7', 'a80825a21757a851dd3b21cc3caed660']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,1036) == "a9d8654475cb556fb1cf62b83e2fa778"
}

