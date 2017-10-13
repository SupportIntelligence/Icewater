import "hash"

rule m3ed_31fa510ba6620912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa510ba6620912"
     cluster="m3ed.31fa510ba6620912"
     cluster_size="237 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b6f88f908b1a44bd6c97de1911641b8a', 'a2ee7b8112aa780842d88cd1c71cce22', 'ac43eb73909a3c2e79c1812ed0c5da95']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "c36a39d15c14baf3463d80ea4a137d38"
}

