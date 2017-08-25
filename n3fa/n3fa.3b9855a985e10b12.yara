import "hash"

rule n3fa_3b9855a985e10b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.3b9855a985e10b12"
     cluster="n3fa.3b9855a985e10b12"
     cluster_size="11621 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="adsnare malicious cloud"
     md5_hashes="['06565c7f89b9baf6033fc4bd9bb80bdd', '049afbec5b1cc1e13fbb59bfe71b0499', '03a02e1ef485a595a52dc0e766141a4e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(656896,1152) == "fe18f88aa6207b1ff9ed2c13dd42bf82"
}

