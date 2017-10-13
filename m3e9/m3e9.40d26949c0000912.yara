import "hash"

rule m3e9_40d26949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.40d26949c0000912"
     cluster="m3e9.40d26949c0000912"
     cluster_size="249 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['5216637e20c7721dc62407a398263266', 'c1be9d214b979905c7cdf3e3c0ce1f01', '55802cbdcc1aa20fcfa85f86aa06f98c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20904,1046) == "5b0bd4d16860f26b77f31f4375d198f2"
}

