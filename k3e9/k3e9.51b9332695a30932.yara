import "hash"

rule k3e9_51b9332695a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b9332695a30932"
     cluster="k3e9.51b9332695a30932"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b120b12440882ee4cbd708cb1fef1800', 'a9bf26ae62432696d0ab1fed427a9db9', 'd256397f46eba98e7427a2eac31e25d1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "f34df65d28ccd14185252cc32c64c44d"
}

