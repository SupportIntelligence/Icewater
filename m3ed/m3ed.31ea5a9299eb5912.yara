import "hash"

rule m3ed_31ea5a9299eb5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea5a9299eb5912"
     cluster="m3ed.31ea5a9299eb5912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ab310f130732a7c2e9c8d1e150edcb77', 'ab310f130732a7c2e9c8d1e150edcb77', 'ac072bfb331f0ca727de6d8a1413f6b1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

