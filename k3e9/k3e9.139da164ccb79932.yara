import "hash"

rule k3e9_139da164ccb79932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164ccb79932"
     cluster="k3e9.139da164ccb79932"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9b6b4ac2d40e8236b1cf8e183b9ffd50', 'b5b5ae9b3fe4d3522f273cea2179951f', 'bbb81bb41c74a7103bfc50da64a11930']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13824,256) == "ec22e02fc394a4bc1bc22e32fe38e750"
}

