import "hash"

rule k3e9_3c1d3ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1d3ec9c4000b14"
     cluster="k3e9.3c1d3ec9c4000b14"
     cluster_size="149 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['f3446ca95e6112467a63d0a8ba361d3a', 'd43566d6faee1c298e93e137fedb366e', 'b76520682cd5bd61c2c0bddc51e3bf39']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

