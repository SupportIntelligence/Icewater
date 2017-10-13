import "hash"

rule n3e9_2996ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2996ea48c0000b32"
     cluster="n3e9.2996ea48c0000b32"
     cluster_size="18013 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="urelas symmi gupboot"
     md5_hashes="['05070cf2a887bec0579d9ca7b27320d3', '00f91b77416f4818602edf51ca0a92de', '019315955ebc18ac9fa8fc3d954e9d69']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(254976,1024) == "92c36ad682dbc31fc427dee4cda24d54"
}

