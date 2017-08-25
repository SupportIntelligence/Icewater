import "hash"

rule j3e9_05b4b3accee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.05b4b3accee30912"
     cluster="j3e9.05b4b3accee30912"
     cluster_size="330 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="rootkit dropped laqma"
     md5_hashes="['b8cfaa4bac8be52827101f238379d271', 'd6390ea387cb65be93f15477686f808d', 'c6a23914003c850d42d9252a2b1167f8']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(9728,256) == "7a8bfe4ddcbb05c3ef01c68eaca49ccd"
}

