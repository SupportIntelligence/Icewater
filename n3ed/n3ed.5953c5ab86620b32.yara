import "hash"

rule n3ed_5953c5ab86620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5953c5ab86620b32"
     cluster="n3ed.5953c5ab86620b32"
     cluster_size="279 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['d0602b624f1242f0589602c1c166e610', 'a1b049fc5ed88a9555752f840e566cb9', '39b74609a93d2ba2c642f1f7cadd16d8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

