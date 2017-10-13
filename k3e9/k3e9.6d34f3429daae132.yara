import "hash"

rule k3e9_6d34f3429daae132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6d34f3429daae132"
     cluster="k3e9.6d34f3429daae132"
     cluster_size="3901 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre ipatre waski"
     md5_hashes="['232c71e77683e9171be8f3aaf4459be9', '0420e36f5a36ff4c1e8e92000fc54e7e', '1a89d3fcfe2095869e6f452ea2923d6a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8192,1024) == "2c6c7efefb34c2cc9ece6b483b5722e2"
}

