import "hash"

rule m3e9_636684679d994916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.636684679d994916"
     cluster="m3e9.636684679d994916"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob classic"
     md5_hashes="['ba6f43722fa03d514676aee3e34beba8', 'b3b606c2c67382c8e440b95c7e38495d', 'e4c8271539ca4e8516fd27aeccf4f6a8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(189440,1024) == "64a6f9fa137f9145623faf227205f34c"
}

