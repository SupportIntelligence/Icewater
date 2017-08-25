import "hash"

rule k3e9_139ca164ddb39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca164ddb39932"
     cluster="k3e9.139ca164ddb39932"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a8f82217a3dacc071e450779482cf659', 'a59cd14bb50474def90622f2362afc75', 'c8fb57721aa9c4f1cecc438bdb42fdd7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

