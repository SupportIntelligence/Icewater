import "hash"

rule o3ed_4d96dec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96dec1c4000b12"
     cluster="o3ed.4d96dec1c4000b12"
     cluster_size="580 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a8e90ed521b1f366f7d3e9f27992ae01', '3ce7d0a8d2f44eb874792669938f11e5', '4d847391d7af3de5cef4530d0df4c8f9']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1175552,1024) == "46afa767863a1b6f3ddb5d49841540cf"
}

