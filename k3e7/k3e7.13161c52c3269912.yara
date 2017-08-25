import "hash"

rule k3e7_13161c52c3269912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.13161c52c3269912"
     cluster="k3e7.13161c52c3269912"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="damaged file heuristic"
     md5_hashes="['8a878d3fe9c8598804a18ad79ef033ab', 'cd934c9791c83ce9a30e439014885506', '8a878d3fe9c8598804a18ad79ef033ab']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,1024) == "2692e623739162f952a2636832c29164"
}

