import "hash"

rule k3e9_1e66a29782220120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e66a29782220120"
     cluster="k3e9.1e66a29782220120"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c247c4e001f0a6e81cfcea2eb5bda899', 'aa7c0295f861c38f8021b687c8bb738d', '88619d378ef14154d94557408583f2e9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "76f94909e41b2606eb664d22a535c8d2"
}

