import "hash"

rule n3e9_26b2ccc184000954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.26b2ccc184000954"
     cluster="n3e9.26b2ccc184000954"
     cluster_size="27 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="allaple rahack malicious"
     md5_hashes="['a5f84e874b2b6dacad328edce6aa26ad', 'a2fdae393e463b1428bcb4ec04462500', 'a2fdae393e463b1428bcb4ec04462500']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(87552,1024) == "28440c8fae03dcac5981bfcc2a3cd656"
}

