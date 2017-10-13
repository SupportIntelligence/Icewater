import "hash"

rule k3e9_17e308931ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e308931ee31132"
     cluster="k3e9.17e308931ee31132"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c5d17bfb8504d1402e7ca312ebcb5bda', 'c5d17bfb8504d1402e7ca312ebcb5bda', 'b2cdbcf95362f2fe1591b1ebe87b60d3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "2fb80b5f3b6f045f2a5bf05d2c176dae"
}

