import "hash"

rule m3ed_31fa558ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa558ba6220912"
     cluster="m3ed.31fa558ba6220912"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a78833fe413d33e11fb8fa5a3413f9fb', 'baa7d912f3e6b841fe497bc00eeaa045', 'd488738552c02c9e1aa5046a732aa363']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "c36a39d15c14baf3463d80ea4a137d38"
}

