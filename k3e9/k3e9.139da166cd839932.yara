import "hash"

rule k3e9_139da166cd839932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da166cd839932"
     cluster="k3e9.139da166cd839932"
     cluster_size="146 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ca543a855e1b0ec4f7a8e73786e9b828', 'e60f4ad0cd4fef0afa903297905031dd', 'b56efb0d1ea3146b529b11f6f3bbcbec']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16896,256) == "8289f17bd508c11dbe7ba0413e7e3252"
}

