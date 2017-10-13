import "hash"

rule m3e9_631c96cfc566f312
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c96cfc566f312"
     cluster="m3e9.631c96cfc566f312"
     cluster_size="272 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple madang rahack"
     md5_hashes="['a218edb9a9672cc6006bcae3c7f65ad5', 'ceb7525bed55ad10c331a390680aa210', 'a6f2654c612be3615cb50529e7bc1bee']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188000,1030) == "b0d7521531466420dcf3da22bbbd2221"
}

