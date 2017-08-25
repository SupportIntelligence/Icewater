import "hash"

rule k3e9_51b93306dda30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93306dda30b32"
     cluster="k3e9.51b93306dda30b32"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b6f698d468d0c0063cafc7dab8f07a7a', 'd6613a6f46338285af98e585fba68884', 'e244e9b025ced6fad9cc85bbdc662ec5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,256) == "0ada361202bc0ea441168218f8465512"
}

