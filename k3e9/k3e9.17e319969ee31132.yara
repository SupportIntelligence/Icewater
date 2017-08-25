import "hash"

rule k3e9_17e319969ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e319969ee31132"
     cluster="k3e9.17e319969ee31132"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b60719a8656236f0f9f62e7efc525580', 'b60719a8656236f0f9f62e7efc525580', '9706eb28cd54319827511c55ad8e0753']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19456,256) == "65ad431a2ec2152ce929348c491f71a0"
}

