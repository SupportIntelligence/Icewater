import "hash"

rule n3e9_4256ad2cd9ba5315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4256ad2cd9ba5315"
     cluster="n3e9.4256ad2cd9ba5315"
     cluster_size="5228 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['064a5c738ee4bd16a5df07019914efd5', '0d1cea03866ac772418a4637e745ea3d', '08cc179df0e4e7ba1c0792cf8a212c39']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(712704,1024) == "6e9d1f71c4fc1d15075704839d17b462"
}

