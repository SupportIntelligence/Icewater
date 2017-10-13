import "hash"

rule m3e9_4d349642d8999932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d349642d8999932"
     cluster="m3e9.4d349642d8999932"
     cluster_size="4923 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zegost backdoor zusy"
     md5_hashes="['437cd6e38254212a731772fbc0778d6a', '0532ef26c0a8062ab2559d7dd65ea2ef', '22e2b2314824a0cfa74875b273e4ca82']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(77824,1024) == "39ce4f7e6110f02ff6191ffd00ee8e9b"
}

