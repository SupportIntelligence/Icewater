import "hash"

rule m3e9_3a59b3b9caa00b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a59b3b9caa00b14"
     cluster="m3e9.3a59b3b9caa00b14"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="otwycal wapomi vjadtre"
     md5_hashes="['eb54df9f7b0cc6b21f65ed97f18a3cb3', 'af07e8684c380d379fa1e16e2a26e82f', 'd99581acebd2b6ef01160caa09ef81ae']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

