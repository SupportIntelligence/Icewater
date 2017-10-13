import "hash"

rule n3e9_31ca9369c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca9369c8800932"
     cluster="n3e9.31ca9369c8800932"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy orbus malicious"
     md5_hashes="['a2cee7ccf046bc5886316e5622b67fc1', 'b8c8fbd1253196c7a34641a9a6042219', 'cc5510fe9d117f41567c9c0b13b0f64d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1e234acf0ceca011affdfbe810ca8553"
}

