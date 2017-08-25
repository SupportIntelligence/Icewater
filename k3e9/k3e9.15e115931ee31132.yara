import "hash"

rule k3e9_15e115931ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e115931ee31132"
     cluster="k3e9.15e115931ee31132"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['aca5a585f2e8d3e00e2c1dc6762b1ef7', 'b2540f973c95c8a0cc62208a9a123ce7', 'babbf28a91c68cfc4ab2da43b2707883']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19200,256) == "3b15958506c859264d98a47823d86ece"
}

