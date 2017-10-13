import "hash"

rule n3e9_119d2a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.119d2a49c0000b12"
     cluster="n3e9.119d2a49c0000b12"
     cluster_size="301 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b2d5ce2b6b1b8c5b6918dc183233e0dc', 'c0751d41be171a01ed566bb63824f8dd', 'bf3b277b0cd6ee0aa9825d6c0cfb1271']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(216576,1024) == "6eede9d26636f0fa95fd0363c44a62a7"
}

