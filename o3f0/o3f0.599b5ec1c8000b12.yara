import "hash"

rule o3f0_599b5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.599b5ec1c8000b12"
     cluster="o3f0.599b5ec1c8000b12"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious fner icloader"
     md5_hashes="['432d85f34ebc319894682304211e1e19', '5f0ff027375211d8e835ed2737f66cc5', '7532e4a8ea847a3afb2c9929b0239d0f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1277952,1024) == "b69707cee6330a74b8375de04f45775d"
}

