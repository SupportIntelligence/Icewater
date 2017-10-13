import "hash"

rule n3ed_51996b44dee30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b44dee30932"
     cluster="n3ed.51996b44dee30932"
     cluster_size="666 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ac2d2d00f5811fb37ee702ccfdfc9089', 'ad59aa2fb7f5d5e36cf6a30a23262259', '3d0fe94e6dcdb9f9ad812fa164ba9cea']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(421888,1024) == "ba308824265f6d0a1a85f89ecc632f54"
}

