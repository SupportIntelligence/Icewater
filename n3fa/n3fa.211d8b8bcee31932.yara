import "hash"

rule n3fa_211d8b8bcee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.211d8b8bcee31932"
     cluster="n3fa.211d8b8bcee31932"
     cluster_size="5411 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="snare snarasite adsnare"
     md5_hashes="['01387d27c17ee24ddca8735387c00cef', '08ca2a0cb035447d349b64e51339d13a', '0446334cdb5c5f921519d8cab6bd96fe']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(561430,1063) == "2e0e216581d18ede78a1b87c32523da6"
}

