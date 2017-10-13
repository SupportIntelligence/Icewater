import "hash"

rule m3ed_31fa4d8ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa4d8ba6220912"
     cluster="m3ed.31fa4d8ba6220912"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['40c7c8d5fe445edcc2016d11cc590a1c', '90e7d836599858edb02418ea707df5af', 'd20c81d658cd2d884fec10b9383d7ddb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

