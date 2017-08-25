import "hash"

rule k3e9_17e319931ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e319931ee31132"
     cluster="k3e9.17e319931ee31132"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['60ced6e4c39eea86b2c31abbff602d37', 'bb7764be5b80a4ec2927f192fd825bfe', '16f4a4f491a7bb0217af2687532bb8d6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,256) == "78a61b01aadc635b263604b6cef57130"
}

