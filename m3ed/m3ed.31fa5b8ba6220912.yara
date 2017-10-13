import "hash"

rule m3ed_31fa5b8ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa5b8ba6220912"
     cluster="m3ed.31fa5b8ba6220912"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['d98e8cf8d9683af1ebd457a1f069bfa0', 'c15739e89333c8e1c9407ee7e1dabd62', 'c15739e89333c8e1c9407ee7e1dabd62']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "c36a39d15c14baf3463d80ea4a137d38"
}

