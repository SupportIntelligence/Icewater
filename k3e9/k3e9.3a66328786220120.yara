import "hash"

rule k3e9_3a66328786220120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3a66328786220120"
     cluster="k3e9.3a66328786220120"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b32cd903d935b3d2efea9df6bf32b4ca', 'a48f9319a72c028e08147fd54aec4671', 'b70ccf39640107cbfb0c84e45e20f5b0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b98c324b2bff1dc76c923acdf9437671"
}

