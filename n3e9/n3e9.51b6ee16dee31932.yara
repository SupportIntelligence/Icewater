import "hash"

rule n3e9_51b6ee16dee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51b6ee16dee31932"
     cluster="n3e9.51b6ee16dee31932"
     cluster_size="3798 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="backdoor simda shiz"
     md5_hashes="['0d1b4b286676e7e48ff31d44c4939c74', '1112a1fb9fded6e460a31dafd0798b64', '36af2e2e9d2089dec8bcd4e448735023']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(230402,1026) == "2a1861d96ff8e479a00d5856749013c5"
}

