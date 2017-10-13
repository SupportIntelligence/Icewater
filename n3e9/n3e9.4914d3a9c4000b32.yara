import "hash"

rule n3e9_4914d3a9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4914d3a9c4000b32"
     cluster="n3e9.4914d3a9c4000b32"
     cluster_size="661 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['07e8742b0a8af1cf8256805077501b43', 'aa95faf26f584802ae25d10bad597519', '231b204b985ba78c952709d23e7ce230']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(3219,1097) == "9dbcdb80646b5cb4bf3285436fc29f56"
}

