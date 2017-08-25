import "hash"

rule k3e9_139ca164dd9b9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca164dd9b9932"
     cluster="k3e9.139ca164dd9b9932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c1cf96718ee55a82239373be5678ccd4', 'a36f4323fd582f0d1c130ff366b1ebc3', '586062158ed4ef45a5207af39ac3ae25']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "de88ae07cff08473a9c10f1d9aaff856"
}

