import "hash"

rule n3e9_591cbbd1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.591cbbd1c4000b32"
     cluster="n3e9.591cbbd1c4000b32"
     cluster_size="1484 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="elzob graftor shiz"
     md5_hashes="['12243f53d1cb2cd7f38143d9d90c6c29', '69f01466a45985387a124b719d998ab0', '60e9a815f64b4c05b30c2b6965aa9862']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(389120,1024) == "4aedae2bd372ee8431731c3101c435e8"
}

