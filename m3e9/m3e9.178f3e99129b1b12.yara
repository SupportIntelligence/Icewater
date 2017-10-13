import "hash"

rule m3e9_178f3e99129b1b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.178f3e99129b1b12"
     cluster="m3e9.178f3e99129b1b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob vetor"
     md5_hashes="['a43ea5146cec32a2288af5c99df76474', 'b4cd7058ac412684b4f722bc00009fe8', '9047bf56f109d193e58bf9215e492e5a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(31744,1024) == "3185a34f2923f1fa768e250be9ebd99c"
}

