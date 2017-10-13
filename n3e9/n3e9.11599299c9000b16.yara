import "hash"

rule n3e9_11599299c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11599299c9000b16"
     cluster="n3e9.11599299c9000b16"
     cluster_size="1141 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['145373b83a914949dfb1492557686bf1', '657005eefcdb306fbc9a3d1ee47c1488', '77820c5bca17777d1b600df43dff7c7b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(195584,1152) == "a65d524274c61b52c50b4f8a9faef5d7"
}

