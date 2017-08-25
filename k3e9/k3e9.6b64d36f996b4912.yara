import "hash"

rule k3e9_6b64d36f996b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f996b4912"
     cluster="k3e9.6b64d36f996b4912"
     cluster_size="39 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['df78d68191534d5d0aeccf05dbef7366', 'df78d68191534d5d0aeccf05dbef7366', '68c85e32a25282e6ae542babb86afda1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,1024) == "23ace600be1fa6482dbaa29f85262422"
}

