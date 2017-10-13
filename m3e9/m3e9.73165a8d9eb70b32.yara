import "hash"

rule m3e9_73165a8d9eb70b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9eb70b32"
     cluster="m3e9.73165a8d9eb70b32"
     cluster_size="272 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swisyn bner mofksys"
     md5_hashes="['f235cfbc406a93e1f6bc172de6414808', '9843791ee3706390fee0e0adbbf24efd', '5fbb670053af25e7cf3eaa85ec09c139']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

