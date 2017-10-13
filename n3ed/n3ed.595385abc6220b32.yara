import "hash"

rule n3ed_595385abc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.595385abc6220b32"
     cluster="n3ed.595385abc6220b32"
     cluster_size="228 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ccd5d34cdc0ed8ae0df4df58b23c94e7', 'dc17a9bc403097276b762cb387a933ca', 'd6fc4067dbeb429238c8a79a20891f33']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

