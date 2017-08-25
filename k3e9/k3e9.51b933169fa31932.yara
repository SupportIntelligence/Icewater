import "hash"

rule k3e9_51b933169fa31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933169fa31932"
     cluster="k3e9.51b933169fa31932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a50358e10dd7a8d6bc4feabac2f44426', '64374e1aba6f8e3d1d461f59232788ff', 'ce98178ba154508b544ca74680af6477']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4864,256) == "a123699e38ecb694dc0255cec9d6cbbb"
}

