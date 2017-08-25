import "hash"

rule k3e9_2914f3e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914f3e9c8000932"
     cluster="k3e9.2914f3e9c8000932"
     cluster_size="68 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['348579f381c2d2bfef3ad11b149a3569', 'c9d9c0c963e3875477dfbf9ed6ec0a64', 'c9cdc9297def87baa7d4925f801a110f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

