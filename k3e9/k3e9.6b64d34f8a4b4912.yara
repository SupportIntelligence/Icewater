import "hash"

rule k3e9_6b64d34f8a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a4b4912"
     cluster="k3e9.6b64d34f8a4b4912"
     cluster_size="64 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['ddeb9d3f8ad0bd4789a5977042b33a85', 'd920733c1b14ea68c2e77ddfca29f3e5', 'b2c69d856143cf33e1694cc0c45d13bf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

