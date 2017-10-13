import "hash"

rule n3e9_169716c9cc000b54
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.169716c9cc000b54"
     cluster="n3e9.169716c9cc000b54"
     cluster_size="410 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['ca5e7961950b5e83c8afb7d2feccbedb', 'b127a967357744f5836f8e3b7bf44108', 'bc42540657d97c040f2f7e2503f15019']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(208384,1024) == "a59a02b84b34fcb15b099714f391535a"
}

